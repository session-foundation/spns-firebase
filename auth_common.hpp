#pragma once
#include <gnutls/abstract.h>

#include <memory>

namespace spns::notifier {

struct privkey_deleter {
    void operator()(gnutls_privkey_t priv) const noexcept;
};
using privkey_ptr = std::unique_ptr<std::remove_pointer_t<gnutls_privkey_t>, privkey_deleter>;

privkey_ptr load_privkey(std::string_view content);

std::string b64_url(std::string_view in);

}  // namespace spns::notifier
