#include <fmt/chrono.h>
#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <oxenmq/auth.h>
#include <oxenmq/oxenmq.h>
#include <sodium.h>
#include <sodium/randombytes.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <CLI/Validators.hpp>
#include <chrono>
#include <csignal>
#include <exception>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <oxen/log/type.hpp>
#include <random>
#include <stdexcept>

#include "google_auth.hpp"
#include "http2_notifier.hpp"
#include "util.hpp"

extern "C" {
#include <pthread.h>
#include <systemd/sd-daemon.h>
}

namespace firebase {

namespace log = oxen::log;

using namespace log::literals;
using namespace std::literals;

// NB: this is copied from spns/hive/subscription.hpp and needs to match!
enum class SUBSCRIBE : int {
    OK = 0,
    BAD_INPUT = 1,
    ERROR = 4,
};

static auto cat = oxen::log::Cat("firebase");

// Drop a notification after this many attempts (i.e. retry this many minus 1 times).  Note that
// retries back off exponential, so 11 attempts needing 10 retries would take
// 1+2+4+8+16+32+64+128+256+512 = 1023 seconds (~17 minutes), and so going high here isn't
// particularly useful.  (Also note that retries are not attempted across restarts).
inline constexpr int MAX_ATTEMPTS = 11;

// Relative jitter for retry delay.  E.g. a draw from this returns 0.9 and our pre-jitter retry time
// would be 8s, then we actually wait 7.2s.  Should be centered around 1.
thread_local std::uniform_real_distribution<double> retry_jitter{0.75, 1.25};

thread_local std::mt19937_64 rng{std::random_device{}()};

int run(int argc, char* argv[]) {

    CLI::App app{"SPNS firebase notifier"};

    std::filesystem::path auth_file;
    std::string notifier_id = "firebase";
    std::string log_level = "info";
    std::string hivemind_sock = "ipc://./hivemind.sock";
    int hivemind_ping = 5;
    std::filesystem::path x25519_seed = "./firebase_key_x25519";

    app.add_option(
               "--auth",
               auth_file,
               "JSON file containing google 'service_account' authentication details")
            ->required()
            ->check(CLI::ExistingFile);
    app.add_option(
               "--log-level", log_level, "General log level and/or category-specific log levels")
            ->capture_default_str();
    app.add_option(
               "--hivemind",
               hivemind_sock,
               "OxenMQ socket on which the main spns-hivemind is listening for notifier "
               "connections")
            ->capture_default_str();

    app.add_option(
               "--ping",
               hivemind_ping,
               "How often (in seconds) we ping the main spns-hivemind with re-registration and "
               "stats updates")
            ->capture_default_str();

    app.add_option(
               "--notifier-id",
               notifier_id,
               "SPNS notification subsystem ID; notification subscriptions specify this when "
               "subscribing to use this notification service.")
            ->capture_default_str();
    app.add_option(
               "--x25519-seed",
               x25519_seed,
               "Path to a 32-byte X25519 seed to use for persistent keypair.  Should be unique if "
               "running multiple instances connected to the same hivemind.  The file will be "
               "generated if it does not exist")
            ->capture_default_str();

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    log::add_sink(oxen::log::Type::Print, "stderr");
    if (log_level.find("logging") == std::string::npos)
        log_level += ", logging=warn";
    log::apply_categories(log_level);

    if (sodium_init() < 0) {
        log::critical(cat, "sodium init failed; unable to continue!");
        return 10;
    }

    std::string seckey, pubkey;
    try {
        std::string seed;
        if (exists(x25519_seed)) {
            seed = firebase::file::slurp(x25519_seed);
            if (seed.size() == 2 * crypto_box_SEEDBYTES + 1 && seed.back() == '\n')
                seed.pop_back();
            if (seed.size() == 2 * crypto_box_SEEDBYTES && oxenc::is_hex(seed))
                seed = oxenc::from_hex(seed);
            else if (seed.size() != crypto_box_SEEDBYTES)
                throw std::runtime_error{
                        "Invalid --x25519-seed file: expected {} bytes or {} hex digits"_format(
                                crypto_box_SEEDBYTES, crypto_box_SEEDBYTES * 2)};
        } else {
            seed.resize(crypto_box_SEEDBYTES);
            randombytes_buf(seed.data(), seed.size());
            file::dump(x25519_seed, oxenc::to_hex(seed));
        }

        pubkey.resize(crypto_box_PUBLICKEYBYTES);
        seckey.resize(crypto_box_SECRETKEYBYTES);
        crypto_box_seed_keypair(
                reinterpret_cast<unsigned char*>(pubkey.data()),
                reinterpret_cast<unsigned char*>(seckey.data()),
                reinterpret_cast<const unsigned char*>(seed.data()));
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load or generate --x25519-seed: {}", e.what());
        return 1;
    }

    oxenmq::address hivemind_s;
    try {
        hivemind_s = oxenmq::address{hivemind_sock};
    } catch (const std::exception& e) {
        log::error(cat, "Invalid --hivemind socket address: {}", e.what());
        return 1;
    }

    // Block all signals so that spawned threads won't handle them.  We'll set up a signal handler
    // in the main thread below to handle them.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR2);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    std::optional<PyAuthRequestor> authreq;
    try {
        authreq.emplace(std::move(auth_file));
    } catch (const std::exception& e) {
        log::error(cat, "Unable to initialize auth requester: {}", e.what());
        return 1;
    }

    log::debug(cat, "SPNS Firebase Notifier initialized; requesting initial auth token");

    auto [token, expires] = authreq->new_auth_token();
    log::info(cat, "SPNS Firebase Notifier initialized and authenticated with Google");

    auto hn = std::make_optional<HTTP2Notifier>(authreq->project_id(), token);

    log::info(cat, "Starting OxenMQ for SPNS hivemind interaction");
    auto omq = std::make_optional<oxenmq::OxenMQ>(
            std::move(pubkey), std::move(seckey), false, [](auto) { return ""s; });

    auto ncat = omq->add_category("notifier", oxenmq::AuthLevel::basic);

    ncat.add_request_command("validate", [&notifier_id](oxenmq::Message& m) {
        // notifier.validate: Called when a device registered for push notifications.  We get passed
        // some json containing the registration details.  Currently all we look for is a "token"
        // key containing a non-empty string value.
        //
        // Returns a two-part or three-part value: a stringified numeric code from SUBSCRIBE, and an
        // opaque value for the main SPNS to store and feed back to us when this account is to be
        // notified.  (Currently we simply return the device token for this value).  The third value
        // contains "extra" context data that will be fed back to us in push notifications if we
        // provide it, but we currently don't provide it.

        if (m.data.size() != 2) {
            log::warning(cat, "Internal error: invalid input to notifier.validate");
            m.send_reply("ERROR", "Invalid validate request data");
            return;
        }
        if (m.data[0] != notifier_id) {
            log::warning(
                    cat,
                    "Internal error: notifier validate called with unexpected notifier id '{}' != "
                    "'{}'",
                    m.data[0],
                    notifier_id);
            m.send_reply("ERROR", "Invalid notifier value");
            return;
        }

        std::string token;
        try {
            auto data = nlohmann::json::parse(m.data[1]);
            token = data["token"].get<std::string>();
        } catch (const std::exception& e) {
            log::warning(cat, "Unable to parse notifier.validate JSON input: {}", e.what());
            m.send_reply(
                    "{}"_format(static_cast<int>(SUBSCRIBE::BAD_INPUT)),
                    "Unparseable JSON notification request data");
            return;
        }
        if (token.empty()) {
            log::warning(cat, "notifier.validate called with empty notification token");
            m.send_reply(
                    "{}"_format(static_cast<int>(SUBSCRIBE::BAD_INPUT)),
                    "Firebase device token cannot be empty");
            return;
        }
        log::debug(cat, "notifier.validate validated token {}", token);
        m.send_reply("{}"_format(static_cast<int>(SUBSCRIBE::OK)), token);
    });

    struct {
        std::atomic<int64_t> success = 0;  // Total successful notifications, *including* retries.
        std::atomic<int64_t> retry_success = 0;  // Successful notifications but only after a retry.
        std::atomic<int64_t> failures =
                0;  // Failures (i.e. could not retry or too many failed retries)
    } stats;

    std::function<void(firebase::notification n, int code, std::string resp_body)> handle_response;
    handle_response = [&hn, &stats, &handle_response](
                              firebase::notification n, int code, std::string resp_body) {
        bool hit_quota = false;
        // Error codes: see https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
        switch (code) {
            case 200:
                stats.success++;
                if (n.attempts)
                    stats.retry_success++;
                log::trace(cat, "sent notification to {}", n.token);
                return;
            case 400:
                // This is a generic "INVALID_ARGUMENT".  This could be a malformed request, or an
                // invalid token.  There's a deeply nested value in the body that helps us
                // distinguish:
                try {
                    auto err_det0 = nlohmann::json::parse(resp_body)["error"]["details"][0];
                    if (err_det0["@type"].get<std::string_view>() ==
                                "type.googleapis.com/google.firebase.fcm.v1.FcmError" &&
                        err_det0["errorCode"].get<std::string_view>() == "INVALID_ARGUMENT") {
                        log::warning(
                                cat,
                                "Device token {} is no longer valid; adding to ignore list",
                                n.token);
                        stats.failures++;
                        hn->ignore(std::move(n.token));
                        return;
                    }
                } catch (...) {
                }

                // Otherwise this is some other sort of error so log it and schedule a retry
                log::warning(
                        cat, "Notification request returned 400 error with body:\n{}", resp_body);
                break;
            case 401:
                // THIRD_PARTY_AUTH_ERROR.  This seems to be for when you are deeply truely cursed
                // by having decided to use Firebase to send notifications to APNS to make sure that
                // both Google and Apple get to see all your notifications.
                log::warning(
                        cat,
                        "Notification request returned 401, this is unexpected!  Body:\n{}",
                        resp_body);
                break;
            case 403:
                // SENDER_ID_MISMATCH -- the client app registered for FCM but
                // apparently didn't include us as an allowed sender.
                log::warning(
                        cat,
                        "Device token {} has not authorized us to send "
                        "notifications; adding to ignore list",
                        n.token);
                stats.failures++;
                hn->ignore(std::move(n.token));
                return;
            case 404:
                // UNREGISTERED -- the token is not registered, perhaps because the token got
                // refreshed, the app got uninstalled, etc.
                log::warning(
                        cat,
                        "Device token {} unregistered from FCM; adding to ignore list",
                        n.token);
                stats.failures++;
                hn->ignore(std::move(n.token));
                return;
            case 429:
                // QUOTA_EXCEEDED -- we hit some sort of quota, but it could be
                // either for this token specifically or for the project overall.
                log::warning(cat, "Exceeded quota sending to token {}; will retry in 60s", n.token);
                hit_quota = true;
                break;
            default:
                log::warning(
                        cat,
                        "Error code {} while sending to token {}; will retry soon",
                        code,
                        n.token);
                break;
        }

        double retry_seconds = 1 << n.attempts++;

        // If we get here then it failed, but can be retried.  We use an exponential backoff with
        // jitter, as per Google recommendations.
        if (n.attempts >= MAX_ATTEMPTS) {
            log::warning(
                    cat,
                    "Too many notification attempts ({}) for token {}; dropping notification",
                    n.attempts,
                    n.token);
            stats.failures++;
            return;
        }

        if (hit_quota && retry_seconds < 60)
            retry_seconds = 60;
        retry_seconds *= retry_jitter(rng);

        log::debug(cat, "Retrying push to token {} in {:.3f}s", n.token, retry_seconds);

        auto retry_in = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::duration<double>{retry_seconds});

        hn->send_later(retry_in, std::move(n), handle_response);
    };

    ncat.add_command("push", [&notifier_id, &hn, &stats, &handle_response](oxenmq::Message& m) {
        // notifier.push: Called to send a push notification.  This is a command rather than a
        // request (i.e. it does not reply).  The message is a single part, bt-encoded dict (see
        // comments in spns/hivemind.cpp).
        try {
            auto n = notification::parse_spns(m.data.at(0), notifier_id);

            hn->send(std::move(n), handle_response);

        } catch (const std::exception& e) {
            log::warning(cat, "Invalid push: {}", e.what());
        }
    });

    omq->start();
    log::info(cat, "Connecting to SPNS hivemind");
    std::promise<void> omq_prom;
    auto spns_cid = omq->connect_remote(
            hivemind_s,
            [&omq_prom](oxenmq::ConnectionID) { omq_prom.set_value(); },
            [&omq_prom](oxenmq::ConnectionID, std::string_view err) {
                try {
                    throw std::runtime_error{
                            "Failed to connect to SPNS hivemind: {}.  Is spns-hivemind running?"_format(
                                    err)};
                } catch (const std::exception& e) {
                    omq_prom.set_exception(std::current_exception());
                }
            },
            oxenmq::connect_option::ephemeral_routing_id{false},
            oxenmq::connect_option::timeout{10s},
            oxenmq::AuthLevel::basic);
    try {
        omq_prom.get_future().get();
    } catch (const std::exception& e) {
        log::error(
                cat,
                "Failed to connect to spns-hivemind at {}; is spns-hivemind running and is that "
                "the correct address?",
                hivemind_sock);
        return 3;
    }
    log::info(cat, "Connected to SPNS hivemind");
    omq->send(spns_cid, "admin.register_service", notifier_id);

    std::deque<std::tuple<std::chrono::steady_clock::time_point, int64_t, int64_t, int64_t>>
            last_stats;
    std::mutex last_stats_mut;

    auto ping_spns = [&spns_cid, &omq, &notifier_id, &stats, &last_stats, &last_stats_mut] {
        omq->send(spns_cid, "admin.register_service", notifier_id);

        std::map<std::string, int64_t> report;

        std::lock_guard ls_lock{last_stats_mut};
        auto now = std::chrono::steady_clock::now();

        while (!last_stats.empty() && now - std::get<0>(last_stats.front()) > 1h + 1min)
            last_stats.pop_front();
        auto& [now_, s, rs, f] =
                last_stats.emplace_back(now, stats.success, stats.retry_success, stats.failures);
        if (last_stats.size() == 1) {
            report["+notifies"] = s;
            report["+notify_retries"] = rs;
            report["+failures"] = f;
        } else {
            auto& [pnow, ps, prs, pf] = *std::prev(last_stats.end(), 2);
            report["+notifies"] = s - ps;
            report["+notify_retries"] = rs - prs;
            report["+failures"] = f - pf;
        }

        // Don't report any per-day rates unless we have at least a minute of stats to consider
        if (now - std::get<0>(last_stats.front()) >= 1min) {
            for (auto mins : {60, 10, 1}) {
                auto thresh = now - std::chrono::minutes{mins} - 1s;
                auto it = std::lower_bound(
                        last_stats.begin(),
                        last_stats.end(),
                        thresh,
                        [](const auto& s, const auto& thresh) { return std::get<0>(s) < thresh; });
                if (it == last_stats.end())
                    continue;
                const auto& [old_t, old_s, old_rs, old_f] = *it;
                if (old_t >= now)
                    continue;  // Weird; did we stall or something?
                auto notifies = s - old_s;
                report["notifies_per_day.{}m"_format(mins)] =
                        notifies * 86400'000 /
                        std::chrono::duration_cast<std::chrono::milliseconds>(now - old_t).count();
            }
        }

        omq->send(spns_cid, "admin.service_stats", notifier_id, oxenc::bt_serialize(report));
    };

    omq->add_timer(ping_spns, std::chrono::seconds{hivemind_ping <= 0 ? 5 : hivemind_ping});

    // Run this timer once a minute, refreshing if we have less than 20min validity left for the
    // token.  That way even if we get a failure, we can still retry 19 times before the token
    // actually becomes invalid, and if Google starts returning tokens with less than 20min
    // validity, at least we rate limit ourselves to one per minute.
    omq->add_timer(
            [&expires, &token, &authreq, &hn] {
                auto now = std::chrono::system_clock::now();
                if (expires > now + 20min)
                    return;

                try {
                    std::tie(token, expires) = authreq->new_auth_token();
                } catch (const std::exception&) {
                    // Already logged, but log if it's failing and we're nearly expired:
                    if (expires < now)
                        log::error(
                                cat,
                                "Current OAuth2 token expired {} ago!",
                                friendly_duration(now - expires));
                    else if (expires < now + 10min)
                        log::warning(
                                cat,
                                "Current OAuth2 token expires in {}!",
                                friendly_duration(expires - now));
                    return;
                }
                hn->update_auth_token(token);
            },
            1min);

    sd_notify(0, "READY=1\nSTATUS=Started");

    // Schedule our system status update timer through *both* OMQ and quic::Loop event loops so that
    // if there is a problem with either one, we won't update it and the watchdog can kill us.
    omq->add_timer(
            [&loop = hn->loop, &stats, &last_stats, &last_stats_mut] {
                loop.call_get([&stats, &last_stats, &last_stats_mut] {
                    int64_t s = stats.success, rs = stats.retry_success, f = stats.failures;

                    // Go look up our notification rate by looking for oldest value up to a minute
                    // old in last_stats
                    std::lock_guard ls_lock{last_stats_mut};
                    using dseconds = std::chrono::duration<double>;
                    auto now = std::chrono::steady_clock::now();
                    auto thresh = now - 1min;
                    std::string rate_info;
                    auto it = std::lower_bound(
                            last_stats.begin(),
                            last_stats.end(),
                            thresh,
                            [](const auto& s, const auto& thresh) {
                                return std::get<0>(s) < thresh;
                            });
                    if (it != last_stats.end()) {
                        const auto& [t, ls, lrs, lf] = *it;
                        double secs = dseconds{now - t}.count();
                        rate_info = "; last min: {:.1f}n/s, {:.1f}f/s"_format(
                                (s - ls) / secs, (f - lf) / secs);
                    }
                    auto stats = "{} notifs ({} w/ retry), {} failed{}"_format(s, rs, f, rate_info);
                    log::debug(cat, "Stats: {}", stats);
                    sd_notify(0, "WATCHDOG=1\nSTATUS={}"_format(stats).c_str());
                });
            },
            1s);

    // Run forever/until we get a signal to stop
    int signum = 0;
    sigwait(&sigset, &signum);
    log::warning(cat, "Caught signal {}, shutting down", signum);
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");

    // Stop OxenMQ first so that we won't get new incoming pushes.  Pushes will back up on the SPNS
    // socket and get delivered to us when we restart and restablish the connection.
    log::info(cat, "Stopping OxenMQ...");
    omq.reset();
    log::info(cat, "Stopping HTTP2 notification client...");
    hn->stop();
    hn.reset();
    log::info(cat, "Shutdown complete.");

    return 0;
}

}  // namespace firebase

int main(int argc, char* argv[]) {
    return firebase::run(argc, argv);
}
