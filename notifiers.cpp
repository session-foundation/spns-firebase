#include "notifiers.hpp"

#include <oxenc/hex.h>
#include <oxenmq/address.h>
#include <oxenmq/oxenmq.h>
#include <sodium/core.h>
#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>

#include <CLI/CLI.hpp>
#include <csignal>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "util.hpp"

extern "C" {
#include <pthread.h>
#include <systemd/sd-daemon.h>
}

namespace spns::notifier {

static auto cat = log::Cat("spns");

NotifierBase::NotifierBase(CLI::App& app, std::string notifier_id_) :
        notifier_id{std::move(notifier_id_)} {

    log::add_sink(oxen::log::Type::Print, "stderr");

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

    app.add_flag(
            "--no-unsubscribe",
            no_unsubscribe,
            "Disable automatic unsubscription of expired/invalid account IDs (for "
            "testing/debugging purposes).");

    app.add_option(
            "--x25519-seed",
            x25519_seed,
            "Path to a 32-byte X25519 seed to use for persistent keypair.  Should be unique if "
            "running multiple instances connected to the same hivemind.  "
            "'<notifierid>_key_x25519' is used if not specified.  Will be generated if it does "
            "not exist");
}

oxenmq::OxenMQ& NotifierBase::init() {

    namespace log = oxen::log;

    if (log_level.find("logging") == std::string::npos)
        log_level += ", logging=warn";
    log::apply_categories(log_level);

    if (sodium_init() < 0)
        throw std::runtime_error{"sodium init failed; unable to continue!"};

    std::string seckey, pubkey;
    try {
        if (x25519_seed.empty())
            x25519_seed = "{}_key_x25519"_format(id());

        std::string seed;
        if (exists(x25519_seed)) {
            seed = file::slurp(x25519_seed);
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
        throw std::runtime_error{"Failed to load or generate --x25519-seed: {}"_format(e.what())};
    }

    try {
        hivemind_s = oxenmq::address{hivemind_sock};
    } catch (const std::exception& e) {
        throw std::runtime_error{"Invalid --hivemind socket address: {}"_format(e.what())};
    }

    // Block all signals so that spawned threads won't handle them.  We'll set up a signal handler
    // in the main thread below to handle them.
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR2);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    omq.emplace(std::move(pubkey), std::move(seckey), false, [](auto) { return ""s; });
    return *omq;
}

void NotifierBase::start(oxen::quic::Loop& qloop) {
    loop = &qloop;

    omq->start();
    log::info(cat, "Connecting to SPNS hivemind");
    std::promise<void> omq_prom;
    spns_cid = omq->connect_remote(
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
        throw std::runtime_error{
                "Failed to connect to spns-hivemind at {}; is spns-hivemind running and is that "
                "the correct address?"_format(hivemind_sock)};
    }

    log::info(cat, "Connected to SPNS hivemind");

    omq->send(spns_cid, "admin.register_service", notifier_id);

    omq->add_timer(
            [this] {
                omq->send(spns_cid, "admin.register_service", notifier_id);

                std::map<std::string, int64_t> report;

                std::lock_guard ls_lock{last_stats_mut};
                auto now = std::chrono::steady_clock::now();

                while (!last_stats.empty() && now - std::get<0>(last_stats.front()) > 1h + 1min)
                    last_stats.pop_front();
                auto& [now_, s, rs, f] = last_stats.emplace_back(
                        now, stats.success, stats.retry_success, stats.failures);
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

                // Don't report any per-day rates unless we have at least a minute of stats to
                // consider
                if (now - std::get<0>(last_stats.front()) >= 1min) {
                    for (auto mins : {60, 10, 1}) {
                        auto thresh = now - std::chrono::minutes{mins} - 1s;
                        auto it = std::lower_bound(
                                last_stats.begin(),
                                last_stats.end(),
                                thresh,
                                [](const auto& s, const auto& thresh) {
                                    return std::get<0>(s) < thresh;
                                });
                        if (it == last_stats.end())
                            continue;
                        const auto& [old_t, old_s, old_rs, old_f] = *it;
                        if (old_t >= now)
                            continue;  // Weird; did we stall or something?
                        auto notifies = s - old_s;
                        report["notifies_per_day.{}m"_format(mins)] =
                                notifies * 86400'000 /
                                std::chrono::duration_cast<std::chrono::milliseconds>(now - old_t)
                                        .count();
                    }
                }

                omq->send(
                        spns_cid, "admin.service_stats", notifier_id, oxenc::bt_serialize(report));
            },
            std::chrono::seconds{hivemind_ping <= 0 ? 5 : hivemind_ping});

    omq->add_timer(
            [this] {
                auto bad = loop->call_get([this] {
                    std::unordered_set<std::string> bad;
                    std::swap(bad, bad_tokens);
                    return bad;
                });

                log::debug(cat, "{} bad tokens to remove from SPNS", bad.size());
                if (!bad.empty()) {
                    if (no_unsubscribe)
                        log::warning(
                                cat,
                                "{} registrations to be dropped, but ignoring because of "
                                "--no-unsubscribe flag",
                                bad.size());
                    else
                        omq->send(
                                spns_cid,
                                "admin.drop_registrations",
                                notifier_id,
                                oxenc::bt_serialize(bad));
                }
            },
            15s);
}

void NotifierBase::run() {
    sd_notify(0, "READY=1\nSTATUS=Started");

    // Schedule our system status update timer through *both* OMQ and quic::Loop event loops so that
    // if there is a problem with either one, we won't update it and the watchdog can kill us.
    omq->add_timer(
            [this] {
                loop->call_get([this] {
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
                    if (auto now = std::chrono::steady_clock::now();
                        now >= last_stats_log + 59'500ms) {
                        log::info(cat, "Stats: {}", stats);
                        last_stats_log = now;
                    } else {
                        log::debug(cat, "Stats: {}", stats);
                    }
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
}

void NotifierBase::bad_token(std::string token) {
    assert(loop);  // Should have already called start
    loop->call([this, t = std::move(token)]() mutable { bad_tokens.insert(std::move(t)); });
}

}  // namespace spns::notifier
