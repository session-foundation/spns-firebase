#pragma once
#include <curl/curl.h>
#include <curl/multi.h>

#include <chrono>
#include <oxen/quic/loop.hpp>
#include <span>
#include <string>
#include <unordered_set>

#include "notification.hpp"

using namespace std::literals;

struct event;

namespace firebase {

class HTTP2Notifier {
    CURLM* multi;
    curl_socket_t sockfd;

    bool stopping = false;
    std::promise<void> last_stopped;

    const std::string url;

    std::unordered_set<CURL*> handles;

    // Contains the current request headers.  If the headers change (i.e. because the auth token
    // changes) then we replace this shared pointer with the new header list, but each request also
    // has a shared_ptr copy of this (which it needs to hold onto until the handle finishes).
    std::shared_ptr<curl_slist> req_headers;

    // Updates `req_headers` to a new linked list containing the common request headers plus the
    // given auth token to insert into an Authorization header.
    void replace_headers(std::string_view auth_token);

    std::chrono::milliseconds req_timeout = 10s;

    // Ignored tokens, because of a previous rejection by upstream Firebase.  The value is the
    // expiry after which we will try sending to this token again.
    std::unordered_map<std::string, std::chrono::system_clock::time_point> ignored;
    std::shared_ptr<oxen::quic::Ticker> ignored_cleaner;

    static int handle_socket_c(CURL* easy, curl_socket_t s, int action, void* userp, void* socketp);
    static int start_timeout_c(CURLM* multi, long timeout_ms, void* userp);
    static void curl_perform_c(int /*fd*/, short event, void* cctx);
    void on_timeout();
    void check_multi_info();

    ::event* ev_timeout;

    friend struct curl_context;

  public:
    // Event loop used for HTTP.  Can also be used externally (e.g. for scheduling retries or auth
    // token updates).
    oxen::quic::Loop loop;

    // Version we send in notifications indicating our version (so that, in theory, clients can
    // treat our responses differently in case we need to coordinate a behavioural change with
    // android client updates).
    static inline constexpr int VERSION = 2;

    // Constructs a curl FCM notifier.  Constructing the object starts a thread to manage all curl
    // connections.  The thread stops during object destruction.
    //
    // project_id is the App store project slug, generally something like "myproject-8b78e"
    // auth_token is the initial auth token value to send for authentication (see google_auth.hpp).
    // (Note that auth tokens only last for hours, and need to be updated periodically).
    HTTP2Notifier(std::string_view project_id, std::string_view auth_token);

    // Gracefully stops, waiting for any currently active requests to finish before this returns.
    // This must not be called from within the event loop thread itself!
    void stop();

    // Stops and joins the curl thread, cancelling any ongoing requests.
    ~HTTP2Notifier();

    // Set the timeout for future requests.  Does not affect in-progress requests.
    void set_timeout(std::chrono::milliseconds timeout);

    // Updates the authorization bearer token used for requests submitted after this call.
    void update_auth_token(std::string auth_token);

    // Submits a new notification message.  When the response arrives, the given callback is
    // invoked with it.
    //
    // Arguments:
    // - payload - the nonce+encrypted payload value, in raw bytes.  (Will be b64 encoded).
    // - token - the device token, some magic string given to us by the client during push
    //   registration.
    // - high_priority - true if this should be flagged as high priority, false for normal priority.
    //   Google might apparently get mad if you deliver too many "high" priority items that don't
    //   actually create notifications, so try to make this non-high for things like config messages
    //   and other namespaces that definitely aren't messages.
    //
    // When we get the response (success or failure), the callback is invoked (if given) with the
    // result code and the token so that the caller can decide what to do with it.
    //
    // The callback is *not* called if the input token is on the ignored token list, or if the
    // request is cancelled (e.g. by object destruction) before the request completes.
    void send(
            notification n,
            std::function<void(notification n, int code, std::string resp_body)> callback);

    // Schedules a delayed send (typically for a retry) to be called after the specified duration.
    // The first argument is the delay and the remaining arguments are to be given to send() after
    // the delay.
    void send_later(
            std::chrono::microseconds delay,
            notification n,
            std::function<void(notification n, int code, std::string resp_body)> callback);

    // Called to pass a token to be ignored, i.e. when we got a response back from Google that it is
    // invalid.  Any call to `send` with an ignored token will be dropped.
    //
    // Timeout: how long it gets ignored.  We will clear it from the ignore list after
    // (approximately) the given time.
    //
    // TODO: we should really transmit these back to the spns hivemind to be deleted from it.
    void ignore(std::string token, std::chrono::seconds ignore_for = 24h);
};

}  // namespace firebase
