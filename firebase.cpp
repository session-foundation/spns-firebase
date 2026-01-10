#include <fmt/chrono.h>
#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <oxenmq/auth.h>
#include <oxenmq/oxenmq.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <CLI/Validators.hpp>
#include <exception>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <oxen/log/type.hpp>

#include "google_auth.hpp"
#include "http2_notifier.hpp"
#include "notifiers.hpp"
#include "util.hpp"

extern "C" {
#include <pthread.h>
#include <systemd/sd-daemon.h>
}

static auto cat = oxen::log::Cat("firebase");

namespace spns::notifier::firebase {

int run(int argc, char* argv[]) {

    CLI::App app{"SPNS firebase notifier"};

    NotifierBase nb{app, "firebase"};

    std::filesystem::path auth_file;

    app.add_option(
               "--auth",
               auth_file,
               "JSON file containing google 'service_account' authentication details")
            ->required()
            ->check(CLI::ExistingFile);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    std::optional<AuthRequestor> authreq;
    try {
        authreq.emplace(std::move(auth_file));
    } catch (const std::exception& e) {
        log::error(cat, "Unable to initialize auth requester: {}", e.what());
        return 1;
    }

    log::debug(cat, "SPNS Firebase Notifier initialized; requesting initial auth token");

    auto [token, expires] = authreq->new_auth_token();

    log::info(cat, "SPNS Firebase Notifier initialized and authenticated with Google");

    auto hn = std::make_optional<FirebaseHTTP>(authreq->project_id(), token);

    auto& omq = nb.init();

    auto ncat = omq.add_category("notifier", oxenmq::AuthLevel::basic);

    ncat.add_request_command("validate", [&nb](oxenmq::Message& m) {
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
        if (m.data[0] != nb.id()) {
            log::warning(
                    cat,
                    "Internal error: notifier validate called with unexpected notifier id '{}' != "
                    "'{}'",
                    m.data[0],
                    nb.id());
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

    std::function<void(notification n, int code, std::string resp_body)> handle_response;
    handle_response = [&nb, &hn, &handle_response](
                              notification n, int code, std::string resp_body) {
        bool invalid_token = false;
        bool hit_quota = false;
        // Error codes: see https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
        switch (code) {
            case 200:
                nb.stats.success++;
                if (n.attempts)
                    nb.stats.retry_success++;
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
                                cat, "Device token {} is no longer valid; deleting it", n.token);
                        invalid_token = true;
                        break;
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
                        "notifications; deleting it",
                        n.token);
                invalid_token = true;
                break;
            case 404:
                // UNREGISTERED -- the token is not registered, perhaps because the token got
                // refreshed, the app got uninstalled, etc.
                log::warning(cat, "Device token {} unregistered from FCM; deleting it", n.token);
                invalid_token = true;
                break;
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

        if (invalid_token) {
            nb.stats.failures++;
            nb.bad_token(n.token);
            hn->ignore(std::move(n.token));
            return;
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
            nb.stats.failures++;
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

    ncat.add_command("push", [&nb, &hn, &handle_response](oxenmq::Message& m) {
        // notifier.push: Called to send a push notification.  This is a command rather than a
        // request (i.e. it does not reply).  The message is a single part, bt-encoded dict (see
        // comments in spns/hivemind.cpp).
        try {
            auto n = notification::parse_spns(m.data.at(0), nb.id());

            hn->send(std::move(n), handle_response);

        } catch (const std::exception& e) {
            log::warning(cat, "Invalid push: {}", e.what());
        }
    });

    log::info(cat, "SPNS Firebase Notifier initialized, starting up");

    nb.start(hn->loop);

    // Run this timer once a minute, refreshing if we have less than 20min validity left for the
    // token.  That way even if we get a failure, we can still retry 19 times before the token
    // actually becomes invalid, and if Google starts returning tokens with less than 20min
    // validity, at least we rate limit ourselves to one per minute.
    omq.add_timer(
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

    nb.run();

    log::info(cat, "Stopping HTTP2 notification client...");
    hn->stop();
    hn.reset();
    log::info(cat, "Shutdown complete.");

    return 0;
}

}  // namespace spns::notifier::firebase

int main(int argc, char* argv[]) {
    try {
        return spns::notifier::firebase::run(argc, argv);
    } catch (const std::exception& e) {
        oxen::log::error(cat, "{}", e.what());
        return 1;
    }
}
