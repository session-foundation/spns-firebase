#include "auth_common.hpp"

#include <oxenc/base64.h>

#include <oxen/log/format.hpp>

namespace spns::notifier {

using namespace oxen::log::literals;

void privkey_deleter::operator()(gnutls_privkey_t priv) const noexcept {
    gnutls_privkey_deinit(priv);
}

privkey_ptr load_privkey(std::string_view content) {
    gnutls_global_init();

    gnutls_datum_t pem_data{
            .data = const_cast<unsigned char*>(
                    reinterpret_cast<const unsigned char*>(content.data())),
            .size = static_cast<unsigned int>(content.size())};

    gnutls_x509_privkey_t x_priv;
    gnutls_x509_privkey_init(&x_priv);
    int ret = gnutls_x509_privkey_import(x_priv, &pem_data, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        gnutls_x509_privkey_deinit(x_priv);
        throw std::invalid_argument{
                "Invalid auth data: did not find a valid PEM private key: {}"_format(
                        gnutls_strerror(ret))};
    }

    privkey_ptr priv;
    {
        gnutls_privkey_t p;
        gnutls_privkey_init(&p);
        priv.reset(p);
    }
    ret = gnutls_privkey_import_x509(priv.get(), x_priv, 0);
    if (ret < 0) {
        gnutls_x509_privkey_deinit(x_priv);
        throw std::invalid_argument{
                "Invalid private key: import failed: {}"_format(gnutls_strerror(ret))};
    }

    return priv;
}

std::string b64_url(std::string_view in) {
    auto out = oxenc::to_base64_unpadded(in);
    for (auto& c : out)
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    return out;
}

}  // namespace spns::notifier
