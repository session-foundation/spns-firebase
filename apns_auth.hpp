#pragma once

#include <chrono>
#include <filesystem>
#include <string>

#include "auth_common.hpp"

namespace spns::notifier::apns {

class AuthSigner {
  private:
    std::string key_id;
    std::string team_id;
    privkey_ptr priv;

  public:
    // Takes the 10-digit "key id", 10-digit team id, and path to an Apple ".p8" private key
    // associated with that key_id, which is just a PEM file containing a private key (see Apple
    // docs about token-based connection to APNs for info on how to generate this).
    explicit AuthSigner(
            std::string key_id, std::string team_id, const std::filesystem::path& privkey);

    // Creates a new JWT to be sent in a "Authorization: bearer <TOKEN>" header to authenticate HTTP
    // requests.  The token includes the current time, and will be good for 1h; rotation is required
    // before that (e.g.  50min).  Apple docs explain that Apple may or may not possibly get mad and
    // do something or nothing if this is regenerated more frequently than once per 20min.
    //
    // Returns the token and the expiry (i.e. current time + 1h) before which the value should be
    // regenerated.
    std::pair<std::string, std::chrono::sys_seconds> new_auth_token();
};

}  // namespace spns::notifier::apns
