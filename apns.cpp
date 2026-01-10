#include <fmt/chrono.h>
#include <oxenc/bt_producer.h>
#include <oxenc/hex.h>
#include <oxenmq/auth.h>
#include <oxenmq/oxenmq.h>

#include <CLI/CLI.hpp>
#include <CLI/Error.hpp>
#include <CLI/Validators.hpp>
#include <chrono>
#include <exception>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <oxen/log/type.hpp>
#include <random>
#include <stdexcept>

#include "apns_auth.hpp"
#include "http2_notifier.hpp"
#include "notifiers.hpp"

static auto cat = oxen::log::Cat("apns");

namespace spns::notifier::apns {

namespace log = oxen::log;
using namespace log::literals;

int run(int argc, char* argv[]) {

    CLI::App app{"SPNS APNs notifier"};

    NotifierBase nb{app, "apns"};

    std::string team_id;
    std::string key_id;
    std::filesystem::path key_file;
    std::string app_id;
    bool sandbox = false;

    app.add_option("--team-id", team_id, "Apple team identifier (10 characters)")->required();
    app.add_option("--key-id", key_id, "Apple key id for authentication (10 characters)")
            ->required();
    app.add_option(
               "--privkey",
               key_file,
               "PEM file containing the Apple secret key associed with --key-id used for request "
               "authentication")
            ->required()
            ->check(CLI::ExistingFile);
    app.add_option("--app-id", app_id, "Apple application/bundle ID")->required();
    app.add_flag(
            "--sandbox",
            sandbox,
            "Run in sandbox mode with pushes to the sandbox APNs; requires a sandbox key");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    std::optional<AuthSigner> tokensigner;
    try {
        tokensigner.emplace(std::move(key_id), std::move(team_id), std::move(key_file));
    } catch (const std::exception& e) {
        throw std::runtime_error{"Unable to initialize auth signer: {}"_format(e.what())};
    }

    auto& omq = nb.init();

    auto [token, expires] = tokensigner->new_auth_token();

    auto hn = std::make_optional<APNSHTTP>(app_id, token, sandbox);

    auto ncat = omq.add_category("notifier", oxenmq::AuthLevel::basic);

    ncat.add_request_command("validate", [&nb](oxenmq::Message& m) {
        // notifier.validate: Called when a device registered for push notifications.  We get passed
        // some json containing the registration details.  Currently all we look for is a "token"
        // key containing a length-64 hex value.
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
        if (token.size() != 64 || !oxenc::is_hex(token)) {
            log::warning(
                    cat,
                    "notifier.validate called with invalid notification token: expected 64 hex "
                    "digits, "
                    "got {} (length {})",
                    token,
                    token.size());
            m.send_reply(
                    "{}"_format(static_cast<int>(SUBSCRIBE::BAD_INPUT)),
                    "Invalid APNs device token (expected 64 hex, got {}B)"_format(token.size()));
            return;
        }
        log::debug(cat, "notifier.validate validated token {}", token);
        m.send_reply("{}"_format(static_cast<int>(SUBSCRIBE::OK)), token);
    });

    std::function<void(notification n, int code, std::string resp_body)> handle_response;
    handle_response = [&hn, &nb, &handle_response](
                              notification n, int code, std::string resp_body) {
        bool invalid_token = false;
        bool hit_quota = false;
        // Error codes: see
        // https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
        if (code == 200) {
            nb.stats.success++;
            if (n.attempts)
                nb.stats.retry_success++;
            log::trace(cat, "successful notification to {}", n.token);
            return;
        }

        // Otherwise, for an error, there is supposed to be a json body with a "reason" key to
        // figure out exactly what happened:
        std::string reason;
        try {
            reason = nlohmann::json::parse(resp_body)["reason"].get<std::string>();
        } catch (...) {
            log::warning(
                    cat,
                    "Unable to parse error {} response; will retry soon.  Response:\n{}",
                    code,
                    resp_body);
        }

        log::debug(cat, "Received non-success response {} (with reason: {})", code, reason);

        if (code == 400 && (reason == "BadDeviceToken"sv || reason == "DeviceTokenNotForTopic"sv)) {
            // This means the token we were given is invalid, and so we should drop it.
            log::warning(cat, "{} '{}'; dropping device subscription(s)", reason, n.token);
            invalid_token = true;
        } else if (code == 410) {
            if (reason == "ExpiredToken")
                log::warning(
                        cat, "Token '{}' is expired; dropping device subscription(s)", n.token);
            else if (reason == "Unregistered")
                log::warning(
                        cat,
                        "Token '{}' is no longer active; dropping device subscription(s)",
                        n.token);
            else
                log::warning(
                        cat, "Unknown 410 reason '{}'; dropping device subscription(s)", reason);
            invalid_token = true;
        } else if (code == 429 && reason == "TooManyRequests") {
            log::warning(
                    cat,
                    "Too many requests to token '{}'; cooldown down that device for ~1min",
                    n.token);
            hit_quota = true;
        } else {
            log::error(
                    cat,
                    "Error submitting PN for '{}': {} ({}).  Will retry soon",
                    n.token,
                    code,
                    reason);
        }

        if (invalid_token) {
            nb.stats.failures++;
            nb.bad_token(n.token);
            hn->ignore(std::move(n.token));
            return;
        }

        double retry_seconds = 1 << n.attempts++;

        // If we get here then it failed, but can be retried.  We use an exponential backoff with
        // jitter, because that's a reasonable Google recommendations and because Apple as usual has
        // no useful documented recommendation or instructions.
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

    log::info(cat, "SPNS APNs Notifier initialized, starting up");

    nb.start(hn->loop);

    // Run this timer every 50m to refresh the token.  (There's no errors to worry about retrying
    // anything if it fails, because the token is simply a self-signed value.)
    omq.add_timer(
            [&expires, &token, &tokensigner, &hn] {
                try {
                    std::tie(token, expires) = tokensigner->new_auth_token();
                } catch (const std::exception& e) {
                    log::critical(cat, "Token signing FAILED: {}", e.what());
                    return;
                }
                hn->update_auth_token(token);
            },
            50min);

    nb.run();

    log::info(cat, "Stopping HTTP2 notification client...");
    hn->stop();
    hn.reset();
    log::info(cat, "Shutdown complete.");

    return 0;
}

}  // namespace spns::notifier::apns

int main(int argc, char* argv[]) {

    try {
        return spns::notifier::apns::run(argc, argv);
    } catch (const std::exception& e) {
        oxen::log::error(cat, "{}", e.what());
        return 1;
    }
}
