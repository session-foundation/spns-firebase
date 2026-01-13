#pragma once

#include <chrono>
#include <filesystem>
#include <string>

#include "auth_common.hpp"

namespace spns::notifier::firebase {

using namespace std::literals;

class AuthRequestor {
  private:
    // Values we parse during construction from the Google-provided "service account" JSON web token
    // file auth file (from which we make a "JWT", pronounced "jot" which makes sense because JWT
    // contains two-thirds of WTF)
    std::string proj_id;  // `project_id` from the jot
    // Space-separated list of URL scope values.  The default is what we need for firebase
    // messaging.
    std::string scopes = "https://www.googleapis.com/auth/firebase.messaging"s;
    std::string iss;  // because "iss" is how you spell "client_email"
    std::string aud;  // and this is how you spell "token_uri"

    privkey_ptr priv;

  public:
    // Takes the path to a Google-provided "service_account" JSON web token file
    explicit AuthRequestor(std::filesystem::path jot);

    // Requests a new Oauth2 token, which should be sent in a "Authorization: Bearer <TOKEN>" header
    // to authenticate HTTP requests, and the expiry time of the token (which will usually be 1 hour
    // from when it was requested).
    //
    // This is a synchronous request, and so shouldn't be done in the main processing thread!
    //
    // Throws if the request fails for some reason.
    std::pair<std::string, std::chrono::sys_seconds> new_auth_token();

    // Returns the project id we parsed out of the jot.
    const std::string& project_id() const { return proj_id; }
};

}  // namespace spns::notifier::firebase
