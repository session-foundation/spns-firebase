#include "http2_notifier.hpp"

#include <curl/curl.h>
#include <event2/event.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>

#include <chrono>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

using namespace std::literals;
using namespace oxen::log::literals;

namespace firebase {

namespace log = oxen::log;

static auto cat = log::Cat("firebase.http");

struct notify_context {
    std::shared_ptr<curl_slist> req_headers;
    std::string req_body;
    notification n;
    std::function<void(notification n, int code, std::string resp_body)> callback;
    std::string response;  // Builds up responses pieces as we receive them
};

constexpr size_t RESPONSE_MAX = 100'000;

namespace {
    extern "C" size_t body_accumulate(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto& ctx = *static_cast<notify_context*>(userdata);
        auto len = size * nmemb;
        if (ctx.response.size() + len > RESPONSE_MAX) {
            log::warning(
                    cat,
                    "Response too large ({} accumulated + {} additional), aborting request",
                    ctx.response.size(),
                    len);
            return CURL_WRITEFUNC_ERROR;
        }
        ctx.response.append(ptr, len);
        return len;
    }
}  // namespace

struct curl_context {
    HTTP2Notifier& hn;
    curl_socket_t sockfd;
    event* evt;

    curl_context(HTTP2Notifier& hn, curl_socket_t fd) :
            hn{hn},
            sockfd{fd},
            evt{::event_new(
                    hn.loop.get_event_base(), sockfd, 0, HTTP2Notifier::curl_perform_c, this)} {}
    ~curl_context() {
        ::event_del(evt);
        ::event_free(evt);
    }
};

void HTTP2Notifier::curl_perform_c(int /*fd*/, short event, void* cctx) {
    int running_handles;
    int flags = 0;
    auto* ctx = static_cast<curl_context*>(cctx);
    auto& hn = ctx->hn;

    if (event & EV_READ)
        flags |= CURL_CSELECT_IN;
    if (event & EV_WRITE)
        flags |= CURL_CSELECT_OUT;

    curl_multi_socket_action(hn.multi, ctx->sockfd, flags, &running_handles);
    // Can't use `ctx` anymore because it might have been destroyed during the above call (typically
    // because the socket is no longer being polled).

    hn.check_multi_info();
}

void HTTP2Notifier::on_timeout() {
    int running_handles;
    curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    check_multi_info();
}

int HTTP2Notifier::start_timeout_c(CURLM* /*multi*/, long timeout_ms, void* userp) {
    auto& hn = *static_cast<HTTP2Notifier*>(userp);
    evtimer_del(hn.ev_timeout);
    if (timeout_ms >= 0) {
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (timeout_ms == 0)
            tv.tv_usec = 1; /* 0 means call socket_action asap */
        evtimer_add(hn.ev_timeout, &tv);
    }
    return 0;
}

int HTTP2Notifier::handle_socket_c(
        CURL* /*easy*/, curl_socket_t s, int action, void* userp, void* socketp) {
    assert(userp);
    auto& hn = *static_cast<HTTP2Notifier*>(userp);
    auto* curl_ctx = static_cast<curl_context*>(socketp);
    int events = 0;

    switch (action) {
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
            if (!curl_ctx) {
                curl_ctx = new curl_context{hn, s};
                curl_multi_assign(hn.multi, s, curl_ctx);
            }

            if (action != CURL_POLL_IN)
                events |= EV_WRITE;
            if (action != CURL_POLL_OUT)
                events |= EV_READ;

            events |= EV_PERSIST;

            event_del(curl_ctx->evt);
            event_assign(
                    curl_ctx->evt,
                    hn.loop.get_event_base(),
                    curl_ctx->sockfd,
                    events,
                    HTTP2Notifier::curl_perform_c,
                    curl_ctx);
            event_add(curl_ctx->evt, NULL);

            break;
        case CURL_POLL_REMOVE:
            if (curl_ctx) {
                curl_multi_assign(hn.multi, s, nullptr);
                delete curl_ctx;
            }
            break;
        default: log::error(cat, "Unexpected socket action {} from libcurl", action);
    }

    return 0;
}

void HTTP2Notifier::check_multi_info() {
    int pending;
    while (CURLMsg* message = curl_multi_info_read(multi, &pending)) {
        if (message->msg == CURLMSG_DONE) {
            notify_context* ctx;
            curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &ctx);
            assert(ctx);

            long http_code = 0;
            if (message->data.result == CURLE_OK)
                curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);

            try {
                if (ctx->callback)
                    ctx->callback(std::move(ctx->n), http_code, std::move(ctx->response));
            } catch (const std::exception& e) {
                log::error(cat, "uncaught exception from notify callback: {}", e.what());
            }
            handles.erase(message->easy_handle);
            curl_multi_remove_handle(multi, message->easy_handle);
            curl_easy_cleanup(message->easy_handle);
            delete ctx;
            if (stopping && handles.empty())
                last_stopped.set_value();
        } else {
            log::warning(
                    cat,
                    "Unexpected/unhandled curl-multi message type: {}",
                    static_cast<int>(message->msg));
        }
    }
}

HTTP2Notifier::HTTP2Notifier(std::string_view project_id, std::string_view auth_token) :
        url{"https://fcm.googleapis.com/v1/projects/{}/messages:send"_format(project_id)} {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    replace_headers(auth_token);
    multi = curl_multi_init();
    curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, &handle_socket_c);
    curl_multi_setopt(multi, CURLMOPT_TIMERDATA, this);
    curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, &start_timeout_c);

    ev_timeout = evtimer_new(
            loop.get_event_base(),
            [](evutil_socket_t /*fd*/, short /*events*/, void* arg) {
                static_cast<HTTP2Notifier*>(arg)->on_timeout();
            },
            this);

    ignored_cleaner = loop.call_every(15s, [this] {
        auto now = std::chrono::system_clock::now();
        std::erase_if(ignored, [&now](const auto& i) { return now >= i.second; });
    });
}

void HTTP2Notifier::stop() {
    if (loop.inside())
        throw std::logic_error{"Cannot stop HTTP2Notifier from within its own event loop thread!"};
    auto [count, fut] = loop.call_get([this]() -> std::pair<size_t, std::future<void>> {
        if (stopping)
            throw std::logic_error{"Cannot call stop() multiple times!"};
        stopping = true;
        if (handles.empty())
            last_stopped.set_value();
        return {handles.size(), last_stopped.get_future()};
    });
    if (count)
        log::info(
                cat,
                "Shutting down HTTP2 notification client; waiting on {} outstanding requests",
                count);
    fut.wait();
    log::info(cat, "HTTP2 notification client stopped.");
}

HTTP2Notifier::~HTTP2Notifier() {
    loop.call_get([this] {
        for (auto* h : handles) {
            curl_multi_remove_handle(multi, h);
            notify_context* ctx;
            curl_easy_getinfo(h, CURLINFO_PRIVATE, &ctx);
            curl_easy_cleanup(h);
            delete ctx;
        }
        handles.clear();
        curl_multi_cleanup(multi);
        multi = nullptr;
        event_free(ev_timeout);
    });
}

void HTTP2Notifier::replace_headers(std::string_view auth_token) {

    curl_slist* headers =
            curl_slist_append(nullptr, "Content-Type: application/json; charset=UTF-8");
    headers = curl_slist_append(headers, "User-Agent: Session Push Notification Server/0");
    headers = curl_slist_append(headers, "Authorization: Bearer {}"_format(auth_token).c_str());
    req_headers.reset(headers, [](curl_slist* headers) { curl_slist_free_all(headers); });

    log::info(cat, "OAuth token updated");
}

void HTTP2Notifier::update_auth_token(std::string auth_token) {
    loop.call([this, auth_token = std::move(auth_token)] { replace_headers(auth_token); });
}

void HTTP2Notifier::set_timeout(std::chrono::milliseconds timeout) {
    loop.call([this, timeout] { req_timeout = timeout; });
}

void HTTP2Notifier::ignore(std::string token, std::chrono::seconds ignore_for) {
    loop.call([this, token = std::move(token), ignore_for]() mutable {
        ignored[std::move(token)] = std::chrono::system_clock::now() + ignore_for;
    });
}

void HTTP2Notifier::send(
        notification n,
        std::function<void(notification n, int code, std::string resp_body)> callback) {

    auto body = nlohmann::json{{"message",
                                {{"data",
                                  {{"enc_payload", oxenc::to_base64(n.nonce_ciphertext)},
                                   {"spns", "{}"_format(VERSION)}}},
                                 {"token", n.token},
                                 {"android", {{"priority", n.high_priority ? "high" : "normal"}}}}}}
                        .dump();

    log::trace(cat, "About to send this for notification to {}:\n{}", n.token, body);

    loop.call([this,
               n = std::move(n),
               callback = std::move(callback),
               body = std::move(body)]() mutable {
        if (ignored.count(n.token)) {
            log::trace(cat, "ignore send to {}: token is on ignore list", n.token);
            return;
        }

        auto* h = curl_easy_init();
        auto* ctx =
                new notify_context{req_headers, std::move(body), std::move(n), std::move(callback)};
        curl_easy_setopt(h, CURLOPT_PRIVATE, ctx);
        curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, req_timeout.count());
        curl_easy_setopt(h, CURLOPT_NOPROGRESS, 1);
        curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        curl_easy_setopt(h, CURLOPT_POST, 1);
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, ctx->req_headers.get());
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, ctx->req_body.size());
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, ctx->req_body.data());
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, &body_accumulate);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, ctx);
#ifndef NDEBUG
        if (cat->level() == log::Level::trace)
            curl_easy_setopt(h, CURLOPT_VERBOSE, 1);
#endif

        curl_multi_add_handle(multi, h);
        handles.insert(h);
    });
}

void HTTP2Notifier::send_later(
        std::chrono::microseconds delay,
        notification n,
        std::function<void(notification n, int code, std::string resp_body)> callback) {

    loop.call_later(delay, [this, n = std::move(n), callback = std::move(callback)]() mutable {
        // Don't submit a retry if we are shutting down.
        if (!stopping)
            send(std::move(n), std::move(callback));
    });
}

}  // namespace firebase
