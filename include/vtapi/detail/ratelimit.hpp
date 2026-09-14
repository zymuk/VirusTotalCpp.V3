#pragma once

#include <algorithm>
#include <chrono>
#include <mutex>
#include <thread>

namespace vtapi {
namespace detail {

// Token bucket used to pace requests against the VT rate limit (default 4/min).
// Capacity is one token, so callers can never burst ahead of the configured
// rate; the "disabled" state (0) skips waiting entirely.
class RateLimiter {
public:
    explicit RateLimiter(double requests_per_minute) {
        if (requests_per_minute <= 0.0) {
            rate_ = 0.0;
            return;
        }
        rate_ = requests_per_minute / 60.0; // tokens per second
        tokens_ = 1.0;
        last_ = std::chrono::steady_clock::now();
    }

    double requests_per_minute() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return rate_ * 60.0;
    }

    void wait() {
        if (rate_ == 0.0)
            return;
        std::unique_lock<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - last_).count();
        last_ = now;
        tokens_ = std::min(1.0, tokens_ + elapsed * rate_);
        if (tokens_ < 1.0) {
            const double need = (1.0 - tokens_) / rate_;
            std::this_thread::sleep_for(std::chrono::duration<double>(need));
            last_ = std::chrono::steady_clock::now();
            tokens_ = 0.0;
        } else {
            tokens_ -= 1.0;
        }
    }

private:
    mutable std::mutex mutex_;
    double rate_ = 0.0;
    double tokens_ = 1.0;
    std::chrono::steady_clock::time_point last_{};
};

} // namespace detail
} // namespace vtapi