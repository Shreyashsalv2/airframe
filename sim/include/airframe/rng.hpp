// Deterministic randomness + virtual time.
//
// Two decisions here carry the whole project:
//
// 1. ONE seeded generator, threaded explicitly through everything that needs
//    randomness. No std::rand, no thread_local engines, no default_random_engine
//    seeded from the clock. Given (seed, scenario, fault) the simulator produces
//    byte-identical output on every run, on every machine.
//
// 2. VIRTUAL TIME. The simulator never sleeps. A 2.4-second association is
//    modelled by advancing a counter, not by blocking. The emitted logs and pcap
//    carry realistic millisecond timings while the whole run finishes in
//    microseconds.
//
// Why that matters: a test suite that sleeps for real is slow AND flaky, because
// wall-clock timing varies with machine load. Virtual time removes both problems
// at once. This is the single most important trick in simulator-based testing.
#pragma once

#include <cstdint>
#include <cmath>
#include <random>
#include <string>

namespace airframe {

class Rng {
public:
    explicit Rng(std::uint64_t seed) noexcept : engine_(static_cast<std::mt19937::result_type>(seed)), seed_(seed) {}

    std::uint64_t seed() const noexcept { return seed_; }

    // Uniform integer in [lo, hi] inclusive.
    int uniform_int(int lo, int hi) noexcept {
        if (lo >= hi) return lo;
        std::uniform_int_distribution<int> d(lo, hi);
        return d(engine_);
    }

    double uniform_real(double lo, double hi) noexcept {
        std::uniform_real_distribution<double> d(lo, hi);
        return d(engine_);
    }

    // True with probability p.
    bool bernoulli(double p) noexcept {
        if (p <= 0.0) return false;
        if (p >= 1.0) return true;
        std::bernoulli_distribution d(p);
        return d(engine_);
    }

    // Normal draw clamped to [lo, hi] — used for RSSI jitter and stage latency,
    // both of which are roughly bell-shaped in reality but must stay in range.
    double normal_clamped(double mean, double stddev, double lo, double hi) noexcept {
        std::normal_distribution<double> d(mean, stddev);
        double v = d(engine_);
        if (v < lo) v = lo;
        if (v > hi) v = hi;
        return v;
    }

    // A realistic stage duration: log-normal-ish, right-skewed. Real network
    // timings have a long right tail (occasional retries), which a symmetric
    // normal distribution would completely miss.
    std::uint32_t stage_ms(std::uint32_t typical, double skew = 0.35) noexcept {
        double base = static_cast<double>(typical);
        double v = base * std::exp(normal_clamped(0.0, skew, -1.2, 2.0));
        if (v < 1.0) v = 1.0;
        return static_cast<std::uint32_t>(v);
    }

    void fill_bytes(std::uint8_t* dst, std::size_t n) noexcept {
        for (std::size_t i = 0; i < n; ++i)
            dst[i] = static_cast<std::uint8_t>(uniform_int(0, 255));
    }

    // Locally-administered unicast MAC (bit 1 of the first octet set, bit 0 clear).
    // Using real OUI ranges in synthetic captures would be actively misleading.
    void fill_mac(std::uint8_t mac[6]) noexcept {
        fill_bytes(mac, 6);
        mac[0] = static_cast<std::uint8_t>((mac[0] | 0x02) & 0xFE);
    }

private:
    std::mt19937  engine_;
    std::uint64_t seed_;
};

// Monotonic virtual clock, in milliseconds since simulator start.
class VirtualClock {
public:
    std::uint64_t now_ms() const noexcept { return now_ms_; }
    void advance(std::uint64_t ms) noexcept { now_ms_ += ms; }
    void reset() noexcept { now_ms_ = 0; }

    // Wall-clock-looking timestamp derived from virtual time, for log lines.
    // Anchored to a fixed epoch so output stays byte-identical across runs —
    // using the real date here would break determinism in a way that is
    // maddening to debug (the diff only appears at midnight).
    std::string timestamp() const;

private:
    std::uint64_t now_ms_ = 0;
};

std::string mac_to_string(const std::uint8_t mac[6]);
bool string_to_mac(const std::string& in, std::uint8_t mac[6]) noexcept;

}  // namespace airframe
