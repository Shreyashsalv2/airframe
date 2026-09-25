#include "airframe/rng.hpp"

#include <cstdio>
#include <cstring>

namespace airframe {

// Fixed anchor: 2025-01-01T00:00:00Z. Deliberately not "now" — see header.
static constexpr std::uint64_t kEpochSeconds = 1735689600ULL;

std::string VirtualClock::timestamp() const {
    const std::uint64_t total_s = kEpochSeconds + now_ms_ / 1000;
    const std::uint32_t ms      = static_cast<std::uint32_t>(now_ms_ % 1000);

    // Days-since-epoch -> civil date, using Howard Hinnant's algorithm. Doing the
    // conversion by hand keeps output identical regardless of the host timezone;
    // localtime()/gmtime() would make the log depend on TZ, which is exactly the
    // kind of hidden input that destroys reproducibility.
    std::int64_t z = static_cast<std::int64_t>(total_s / 86400) + 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const std::uint64_t doe = static_cast<std::uint64_t>(z - era * 146097);
    const std::uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const std::uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::uint64_t mp = (5 * doy + 2) / 153;
    const std::uint64_t d = doy - (153 * mp + 2) / 5 + 1;
    const std::uint64_t m = mp < 10 ? mp + 3 : mp - 9;
    const std::int64_t year = y + (m <= 2 ? 1 : 0);

    const std::uint32_t sod = static_cast<std::uint32_t>(total_s % 86400);
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04lld-%02llu-%02lluT%02u:%02u:%02u.%03uZ",
                  static_cast<long long>(year),
                  static_cast<unsigned long long>(m),
                  static_cast<unsigned long long>(d),
                  sod / 3600, (sod % 3600) / 60, sod % 60, ms);
    return std::string(buf);
}

std::string mac_to_string(const std::uint8_t mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

bool string_to_mac(const std::string& in, std::uint8_t mac[6]) noexcept {
    unsigned v[6];
    if (std::sscanf(in.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                    &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (int i = 0; i < 6; ++i) mac[i] = static_cast<std::uint8_t>(v[i]);
    return true;
}

}  // namespace airframe
