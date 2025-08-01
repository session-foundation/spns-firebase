#include "google_auth.hpp"

#include <fmt/chrono.h>
#include <fmt/std.h>
#include <pybind11/chrono.h>
#include <pybind11/embed.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>

#include <chrono>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <stdexcept>

#include "util.hpp"

namespace firebase {

namespace log = oxen::log;

using namespace log::literals;
using namespace py::literals;

static bool active = false;
static std::mutex py_init_mutex;

static auto cat = log::Cat("firebase.auth");

PyAuthRequestor::PyAuthRequestor(
        std::filesystem::path jot_, const std::vector<std::string>& scopes) :
        jot{std::move(jot_)} {
    {
        std::lock_guard lock{py_init_mutex};
        if (active)
            // pybind11 won't allow us to hold multiple scoped interpreters at once
            throw std::logic_error{
                    "Multiple simultaneous PyAuthRequestor instances are not supported"};
        active = true;
    }

    log::debug(cat, "Parsing auth file {}", jot);
    auto jot_data = nlohmann::json::parse(std::ifstream{jot});
    if (auto t = jot_data.value("type", "(not found)"sv); t != "service_account")
        throw std::invalid_argument{
                "Invalid json auth file: 'type' must be 'service_account', not '{}'"_format(t)};
    proj_id = jot_data.value("project_id", ""s);
    if (proj_id.empty())
        throw std::invalid_argument{"Invalid json auth file: 'project_id' is missing or empty"};

    log::debug(cat, "Initializing Python interpreter");
    try {
        interpreter.emplace();

        Credentials = py::module_::import("google.oauth2.service_account").attr("Credentials");
        Request = py::module_::import("google.auth.transport.requests").attr("Request");
        creds = Credentials.attr("from_service_account_file")(jot.u8string(), "scopes"_a = scopes);
    } catch (py::error_already_set& e) {
        throw std::runtime_error{"Python interpreter initialization: {}"_format(e.what())};
    }
    log::info(cat, "Authentication layer initialized for project {}", proj_id);
}

std::pair<std::string, std::chrono::system_clock::time_point> PyAuthRequestor::new_auth_token() {
    log::debug(cat, "Initiating new auth token request");
    try {
        creds.attr("refresh")(Request());
    } catch (const py::error_already_set& e) {
        log::warning(cat, "Auth token refresh failed: {}", e.what());
        throw std::runtime_error{"Auth token refresh failed: {}"_format(e.what())};
    }

    std::pair<std::string, std::chrono::system_clock::time_point> result{
            creds.attr("token").cast<std::string>(),
            creds.attr("expiry").cast<std::chrono::system_clock::time_point>()};

    log::info(
            cat,
            "New OAuth2 authorization token retrieved, expires in {} ({})",
            friendly_duration(result.second - std::chrono::system_clock::now()),
            result.second);

    return result;
}

}  // namespace firebase
