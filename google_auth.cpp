#include "google_auth.hpp"

#include <curl/curl.h>
#include <fmt/chrono.h>
#include <fmt/std.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <oxenc/base64.h>

#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <stdexcept>

namespace spns::notifier::firebase {

namespace log = oxen::log;

using namespace log::literals;

static auto cat = log::Cat("firebase.auth");

AuthRequestor::AuthRequestor(std::filesystem::path jot) {

    log::debug(cat, "Parsing auth file {}", jot);
    auto jot_data = nlohmann::json::parse(std::ifstream{jot});
    if (auto t = jot_data.value("type", "(not found)"sv); t != "service_account")
        throw std::invalid_argument{
                "Invalid json auth file: 'type' must be 'service_account', not '{}'"_format(t)};
    proj_id = jot_data.value("project_id", ""s);
    if (proj_id.empty())
        throw std::invalid_argument{"Invalid json auth file: 'project_id' is missing or empty"};

    iss = jot_data.value("client_email", ""s);
    if (iss.empty())
        throw std::invalid_argument{"Invalid json auth file: 'client_email' is missing or empty"};

    aud = jot_data.value("token_uri", ""s);
    if (aud.empty())
        throw std::invalid_argument{"Invalid json auth file: 'token_uri' is missing or empty"};

    auto priv_key = jot_data.at("private_key").get<std::string_view>();
    if (priv_key.empty())
        throw std::invalid_argument{"Invalid json auth file: 'private_key' is missing or empty"};

    priv = load_privkey(priv_key);
}

static constexpr auto jot_header = R"({"alg":"RS256","typ":"JWT"})"sv;
static const auto jot_header_b64 = b64_url(jot_header);

std::pair<std::string, std::chrono::sys_seconds> AuthRequestor::new_auth_token() {
    log::debug(cat, "Initiating new auth token request");

    auto iat = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());

    auto claim_b64 = b64_url(nlohmann::json{
            {"iss", iss},
            {"scope", scopes},
            {"aud", aud},
            {"iat", iat.time_since_epoch().count()},
            {"exp", (iat + 1h).time_since_epoch().count()}}
                                     .dump());

    std::string jot = "{}.{}"_format(jot_header_b64, claim_b64);

    // Make the signature by doing a SHA256 of the above jot value, then RSA signing it:
    std::array<unsigned char, 32> hash;
    gnutls_hash_fast(GNUTLS_DIG_SHA256, jot.data(), jot.size(), hash.data());

    const gnutls_datum_t digest{.data = hash.data(), .size = hash.size()};
    gnutls_datum_t sig{};
    if (int r = gnutls_privkey_sign_hash2(
                priv.get(),
                GNUTLS_SIGN_RSA_SHA256,  // RSA-PKCS#1 v1.5 with SHA-256
                0,
                &digest,
                &sig);
        r < 0)
        throw std::runtime_error{"RSA-SHA256 signing failed: {}"_format(gnutls_strerror(r))};

    fmt::format_to(
            std::back_inserter(jot),
            ".{}",
            b64_url({reinterpret_cast<const char*>(sig.data), sig.size}));
    gnutls_free(sig.data);

    // Now submit the signed jot to google auth to get a bearer token we can use
    CURL* curl = curl_easy_init();
    if (!curl)
        throw std::runtime_error{"curl_easy_init failed"};

    std::string postfields =
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}"_format(
                    jot);

    curl_easy_setopt(curl, CURLOPT_URL, aud.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());
    std::string response;
    curl_easy_setopt(
            curl,
            CURLOPT_WRITEFUNCTION,
            +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
                auto* response = static_cast<std::string*>(userdata);
                response->append(ptr, size * nmemb);
                return size * nmemb;
            });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode cr = curl_easy_perform(curl);
    if (cr != CURLE_OK)
        throw std::runtime_error("curl_easy_perform failed");

    curl_easy_cleanup(curl);

    nlohmann::json resp;
    try {
        resp = nlohmann::json::parse(response);
    } catch (const std::exception& e) {
        log::warning(
                cat, "Failed to parse OAuth token request response ({}):\n{}", e.what(), response);
        throw std::runtime_error{"OAuth token request failed"};
    }

    std::pair<std::string, std::chrono::sys_seconds> result;
    auto& [token, expiry] = result;

    if (token = resp.value("access_token", ""s); token.empty()) {
        log::warning(
                cat,
                "OAuth token request failed: no 'access_token' found in response:\n{}",
                response);
        throw std::runtime_error{"OAuth token request failed"};
    }
    if (auto tt = resp.value("token_type", "(missing)"); tt != "Bearer") {
        log::warning(cat, "OAuth token request returned unexpected token type '{}'", tt);
        throw std::runtime_error{"OAuth token request failed"};
    }
    if (auto exp_in = resp.value("expires_in", -1); exp_in >= 600) {
        expiry = iat + std::chrono::seconds{exp_in};
    } else {
        log::warning(
                cat,
                "OAuth token request returned missing or abnormally short expiry: '{}'",
                exp_in);
        throw std::runtime_error{"OAuth token request failed"};
    }

    return result;
}

}  // namespace spns::notifier::firebase
