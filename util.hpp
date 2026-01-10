#pragma once

#include <filesystem>
#include <oxen/log/format.hpp>
#include <string>
#include <string_view>

namespace spns::notifier {

namespace log = oxen::log;

using namespace log::literals;
using namespace std::literals;

namespace file {

    /// Reads a (binary) file from disk into the string `contents`.
    std::string slurp(const std::filesystem::path& filename);

    /// Dumps (binary) string contents to disk. The file is overwritten if it already exists.
    void dump(const std::filesystem::path& filename, std::string_view contents);

}  // namespace file

std::string friendly_duration(std::chrono::nanoseconds dur);

}  // namespace spns::notifier
