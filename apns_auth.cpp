#include "apns_auth.hpp"

#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <oxenc/hex.h>

#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>

#include "auth_common.hpp"
#include "util.hpp"

namespace spns::notifier::apns {

AuthSigner::AuthSigner(
        std::string key_id_, std::string team_id_, const std::filesystem::path& privkey) :
        key_id{std::move(key_id_)},
        team_id{std::move(team_id_)},
        priv{load_privkey(file::slurp(privkey))} {

    if (key_id.size() != 10)
        throw std::invalid_argument{"Invalid key_id: expected 10-digit identifier"};
    if (team_id.size() != 10)
        throw std::invalid_argument{"Invalid team_id: expected 10-digit identifier"};
}

std::pair<std::string, std::chrono::sys_seconds> AuthSigner::new_auth_token() {
    std::pair<std::string, std::chrono::sys_seconds> result;
    auto& [token, now] = result;

    now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());

    token = "{}.{}"_format(
            b64_url(nlohmann::json{{"alg", "ES256"}, {"kid", key_id}}.dump()),
            b64_url(nlohmann::json{{"iss", team_id}, {"iat", now.time_since_epoch().count()}}
                            .dump()));

    const gnutls_datum_t to_sign{
            .data = reinterpret_cast<unsigned char*>(token.data()),
            .size = static_cast<unsigned int>(token.size())};
    gnutls_datum_t sig{};

    int rc = gnutls_privkey_sign_data(priv.get(), GNUTLS_DIG_SHA256, 0, &to_sign, &sig);
    if (rc < 0)
        throw std::runtime_error{"Failed to sign JWT: {}"_format(gnutls_strerror(rc))};

    // Extract the raw 64-byte R || S value for the JWT signature:
    gnutls_datum_t r, s;
    rc = gnutls_decode_rs_value(&sig, &r, &s);
    if (rc < 0) {
        gnutls_free(sig.data);
        throw std::runtime_error{
                "Failed to decode signature for JWT: {}"_format(gnutls_strerror(rc))};
    }
    // The above GNUTLS call is moronic in that it puts a 0 byte on the front to save me from myself
    // in case I am so stupid as to think that an unsigned byte buffer with a high bit in the first
    // byte means the value is negative (and apparently because that sort of stupidity is what the
    // toxic dumpster more formerly known as ASN.1 requires).  So we have to work around that
    // idiocy:
    if (r.size < 32 || r.size > 33 || s.size < 32 || s.size > 33) {
        gnutls_free(sig.data);
        gnutls_free(r.data);
        gnutls_free(s.data);
        throw std::runtime_error{
                "Internal error: expected 32 bytes for R and S, got {} ({}), {} ({})"_format(
                        r.size,
                        oxenc::to_hex(r.data, r.data + r.size),
                        s.size,
                        oxenc::to_hex(s.data, s.data + s.size))};
    }

    std::array<char, 64> rs;
    std::memcpy(rs.data(), r.size == 33 ? r.data + 1 : r.data, 32);
    std::memcpy(rs.data() + 32, s.size == 33 ? s.data + 1 : s.data, 32);
    gnutls_free(sig.data);
    gnutls_free(r.data);
    gnutls_free(s.data);

    token += '.';
    token += b64_url(std::string_view{rs.data(), rs.size()});

    return result;
}

}  // namespace spns::notifier::apns
