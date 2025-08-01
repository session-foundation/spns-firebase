#include "util.hpp"

#include <fstream>
#include <oxen/log/format.hpp>

using namespace std::literals;
using namespace oxen::log::literals;

namespace firebase {
namespace file {

    std::string slurp(const std::filesystem::path& filename) {

        std::ifstream in{filename, std::ios::binary};
        std::string content(
                (std::istreambuf_iterator<char>(in)), (std::istreambuf_iterator<char>()));
        return content;
    }

    void dump(const std::filesystem::path& filename, std::string_view contents) {
        std::ofstream out;
        out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        out.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
        out.write(contents.data(), contents.size());
    }

}  // namespace file

std::string friendly_duration(std::chrono::nanoseconds dur) {
    std::string_view sign = ""sv;
    if (dur < 0ns) {
        sign = "-"sv;
        dur = -dur;
    }

    if (dur >= 24h) {
        auto durh = std::chrono::round<std::chrono::hours>(dur);
        return "{}{}d{}h"_format(sign, durh / 24h, (durh % 24h).count());
    }
    if (dur >= 1h) {
        auto durm = std::chrono::round<std::chrono::minutes>(dur);
        return "{}{}h{}m"_format(sign, durm / 1h, (durm % 1h).count());
    }
    if (dur >= 1min) {
        auto durs = std::chrono::round<std::chrono::seconds>(dur);
        return "{}{}m{}s"_format(sign, durs / 1min, (durs % 1min).count());
    }
    return "{}{:.3f}s"_format(sign, std::chrono::duration<double>{dur}.count());
}

}  // namespace firebase
