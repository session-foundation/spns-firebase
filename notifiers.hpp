#pragma once

#include <oxenmq/connections.h>
#include <oxenmq/oxenmq.h>

#include <CLI/CLI.hpp>
#include <chrono>
#include <filesystem>
#include <oxen/log/format.hpp>
#include <oxen/quic/loop.hpp>
#include <random>
#include <string>
#include <string_view>

namespace spns::notifier {

// NB: this is copied from spns/hive/subscription.hpp and needs to match!
enum class SUBSCRIBE : int {
    OK = 0,
    BAD_INPUT = 1,
    ERROR = 4,
};

// Drop a notification after this many attempts (i.e. retry this many minus 1 times).  Note that
// retries back off exponential, so 11 attempts needing 10 retries would take
// 1+2+4+8+16+32+64+128+256+512 = 1023 seconds (~17 minutes), and so going high here isn't
// particularly useful.  (Also note that retries are not attempted across restarts).
inline constexpr int MAX_ATTEMPTS = 11;

// Relative jitter for retry delay.  E.g. a draw from this returns 0.9 and our pre-jitter retry time
// would be 8s, then we actually wait 7.2s.  Should be centered around 1.
inline thread_local std::uniform_real_distribution<double> retry_jitter{0.75, 1.25};

inline thread_local std::mt19937_64 rng{std::random_device{}()};

class NotifierBase {
  private:
    std::string notifier_id;
    std::string hivemind_sock = "ipc://./hivemind.sock";
    oxenmq::address hivemind_s;
    int hivemind_ping = 5;
    std::filesystem::path x25519_seed;
    std::string log_level = "info";
    bool no_unsubscribe = false;

    std::optional<oxenmq::OxenMQ> omq;
    oxenmq::ConnectionID spns_cid;

    oxen::quic::Loop* loop = nullptr;

    std::deque<std::tuple<std::chrono::steady_clock::time_point, int64_t, int64_t, int64_t>>
            last_stats;
    std::mutex last_stats_mut;

    std::chrono::steady_clock::time_point last_stats_log = std::chrono::steady_clock::now();

    std::unordered_set<std::string> bad_tokens;

    sigset_t sigset;

  public:
    // Construct the options, adding all common options to the given CLI11 app:
    explicit NotifierBase(CLI::App& app, std::string notifier_id);

    // Call this after parsing CLI11 to process the parsed values and initialize various internals
    // (such as oxenmq).
    //
    // Returns a reference to the initialized OxenMQ that the notifier should set up with
    // appropriate endpoints.
    //
    // After endpoints are set up, call start().
    oxenmq::OxenMQ& init();

    // Starts the oxenmq instance.  This will:
    // - connect to hivemind and register the service
    // - start an oxenmq timer to periodically ping/reregister with hivemind and update service
    //   stats with hivemind.
    // - starts a periodic timer to propagate any bad tokens given with `bad_token()` back to
    //   hivemind to be removed from its database.
    //
    // Takes and stores a reference to the quic::Loop object (which should be the one from the
    // HTTP2Notifier) on which to synchronize access to bad_tokens and use for watchdog deadlock
    // checks.
    //
    // After this is called the notifier can add additional timers or do additional random things,
    // but then should call `run()` to give up control.
    void start(oxen::quic::Loop& loop);

    // Runs forver.  This first tells systemd that we are started and starts a watchdog timer, then
    // sets up a signal handler to intercept INT and TERM signals to shut down gracefully and waits
    // forever for it to fire.  At that point it stops oxenmq (so that no new pushes will arrive)
    // and returns control, to allow the notifier to do any remaining cleanup it needs.
    void run();

    std::string_view id() const { return notifier_id; }

    // Notification stats.  These should be incremented appropriately when notifications occur.
    struct {
        std::atomic<int64_t> success = 0;  // Total successful notifications, *including* retries.
        std::atomic<int64_t> retry_success = 0;  // Successful notifications but only after a retry.
        std::atomic<int64_t> failures =
                0;  // Failures (i.e. could not retry or too many failed retries)
    } stats;

    // Can be called to report that a token is no longer valid and should be removed from hivemind.
    void bad_token(std::string token);
};

}  // namespace spns::notifier
