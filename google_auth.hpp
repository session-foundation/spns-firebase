#pragma once

#include <pybind11/embed.h>

#include <chrono>
#include <filesystem>
#include <string>

namespace firebase {

using namespace std::literals;
namespace py = pybind11;

// Retrieves a new auth token from our Google overlords, if they deign to allow it, for
// accessing the firebase notification messaging API.
//
// We do this through an embedded Python interpreter that loads it via Python because the only
// C++ offering available to do this is a truely hideous monorepo monstrosity (which of course
// also brings in things like Google's gigantic, unpleasant Boost imitation (aka abseil).
//
// So for now we just do this via a synchronous Python call.
//
// We keep the interpreter around as long as you keep the PyAuthRequestor around so that
// subsequent requests don't have to spend time starting up the interpreter and loading python
// modules.
//
// This whole thing is basically only marginally better than shelling out to a Python
// interpreter, but the alternatives of doing it all NIH or loading and maintaining use of a
// massive C++ dependency are worse, and given that we only need to use this once every couple
// hours seems bearable.

class __attribute__((visibility("hidden"))) PyAuthRequestor {
  private:
    std::optional<pybind11::scoped_interpreter> interpreter;
    py::object Credentials;
    py::object Request;
    py::object creds;
    const std::filesystem::path jot;
    std::string proj_id;

  public:
    // Takes the path to a Google-provided "service_account" JSON web token file (JWT, which,
    // Google docs tell me, is produced "jot", in much the same way WTF is pronounced
    // "GOO-gul").
    explicit PyAuthRequestor(
            std::filesystem::path jot,
            const std::vector<std::string>& scopes = {
                    "https://www.googleapis.com/auth/firebase.messaging"s});

    // Requests a new Oauth2 token, which should be sent in a "Authorization: Bearer <TOKEN>"
    // header to authenticate HTTP requests, and the expiry time of the token (which appears to
    // generally be 4 hours).
    //
    // This is a synchronous request, and so shouldn't be done in the main processing thread!
    //
    // Throws if the request fails for some reason.
    std::pair<std::string, std::chrono::system_clock::time_point> new_auth_token();

    const std::string& project_id() const { return proj_id; }
};

}  // namespace firebase
