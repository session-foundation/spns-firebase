#include "notification.hpp"

#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/randombytes.h>

#include <nlohmann/json.hpp>
#include <oxen/log/format.hpp>
#include <stdexcept>

namespace spns::notifier {

using namespace oxen::log::literals;

notification::notification(
        std::string token_,
        std::string_view payload,
        std::span<const unsigned char, 32> enc_key,
        bool high_prio) :
        token{std::move(token_)}, high_priority{high_prio} {

    static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == enc_key.size());

    nonce_ciphertext.resize(
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + payload.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);
    std::span<unsigned char> sp{
            reinterpret_cast<unsigned char*>(nonce_ciphertext.data()), nonce_ciphertext.size()};
    auto nonce = sp.first<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>();
    auto ciphertext = sp.subspan(nonce.size());

    randombytes_buf(nonce.data(), nonce.size());
    if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
                     ciphertext.data(),
                     nullptr,
                     reinterpret_cast<const unsigned char*>(payload.data()),
                     payload.size(),
                     nullptr,
                     0,
                     nullptr,
                     nonce.data(),
                     enc_key.data()))
        throw std::runtime_error{"push payload encryption failed!"};
}

notification notification::parse_spns(std::string_view data, std::string_view notifier_id) {
    oxenc::bt_dict_consumer d{data};
    auto svc = d.require<std::string_view>("");
    if (svc != notifier_id)
        throw std::invalid_argument{
                "notifier service '{}' does not much our service id '{}'"_format(svc, notifier_id)};

    // ! contains supplemental data if we gave any, but we currently don't.

    auto msg_id = d.require<std::string_view>("#");

    auto token = d.require<std::string>("&");
    if (token.empty())
        throw std::invalid_argument{"token is empty"};

    // FIXME: once oxenc 1.5 is released, this will work:
    auto account = d.require<std::span<const std::byte, 33>>("@");

    auto enc_key =
            d.require<std::span<const unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>>(
                    "^");

    auto msg_ns = d.require<int16_t>("n");
    auto ts = d.require<int64_t>("t");
    auto expiry = d.require<int64_t>("z");
    // Registrations don't necessarily request data in notifications: if they didn't, this
    // will be omitted, otherwise it will be the encrypted message content (i.e. the data
    // actually stored in the swarm).
    auto msg_data = d.maybe<std::string_view>("~");
    d.finish();

    nlohmann::json metadata{
            {"@", oxenc::to_hex(account)}, {"#", msg_id}, {"n", msg_ns}, {"t", ts}, {"z", expiry}};
    if (msg_data) {
        auto len = msg_data->size();
        metadata["l"] = len;
        if (len > MAX_MSG_SIZE) {
            metadata["B"] = true;
            msg_data.reset();
        }
    }

    std::string payload;
    {
        oxenc::bt_list_producer l;
        l.append(metadata.dump());
        if (msg_data)
            l.append(*msg_data);
        payload = std::move(l).str();
    }
    // Null-pad up to next 256B increment:
    payload.resize((payload.size() + 255) / 256 * 256);

    // Build the encrypted value to be sent:
    return notification{
            std::move(token),
            payload,
            enc_key,
            /*high_prio=*/msg_data && (msg_ns == 0 || msg_ns == 11)};
}

}  // namespace spns::notifier
