cmake_minimum_required(VERSION 3.13...3.31)

project(spns-http2-notifiers
    VERSION 2.0.0
    DESCRIPTION "Session Push Notification Server - HTTP2 notifiers"
    LANGUAGES C CXX)

find_package(CURL REQUIRED COMPONENTS HTTPS SSL HTTP2)
find_package(PkgConfig REQUIRED)

pkg_check_modules(OMQ liboxenmq>=1.2.22 IMPORTED_TARGET REQUIRED)
pkg_check_modules(OXENLOGGING liboxen-logging>=1.2 IMPORTED_TARGET REQUIRED)
pkg_check_modules(CLI11 CLI11>=2.1 IMPORTED_TARGET REQUIRED)
pkg_check_modules(SODIUM libsodium>=1.0.18 IMPORTED_TARGET REQUIRED)
pkg_check_modules(OXENC liboxenc>=1.5 IMPORTED_TARGET REQUIRED)
pkg_check_modules(FMT fmt>=9 IMPORTED_TARGET REQUIRED)
pkg_check_modules(QUIC liboxenquic>=1.6 IMPORTED_TARGET REQUIRED)
pkg_check_modules(GNUTLS gnutls>=3.8 IMPORTED_TARGET REQUIRED)
pkg_check_modules(LIBEVENT_core libevent_core>=2.1 IMPORTED_TARGET REQUIRED)
pkg_check_modules(LIBEVENT_pthreads libevent_pthreads>=2.1 IMPORTED_TARGET REQUIRED)
pkg_check_modules(SYSTEMD libsystemd IMPORTED_TARGET REQUIRED)

add_library(spns-notifier
    auth_common.cpp
    http2_notifier.cpp
    notification.cpp
    notifiers.cpp
    util.cpp
)

target_compile_features(spns-notifier PUBLIC cxx_std_20)

target_link_libraries(spns-notifier
    PUBLIC
    PkgConfig::OMQ
    PkgConfig::OXENLOGGING
    PkgConfig::CLI11
    PkgConfig::FMT
    PkgConfig::OXENC
    PkgConfig::SODIUM
    PkgConfig::QUIC
    PkgConfig::GNUTLS
    PkgConfig::LIBEVENT_core
    PkgConfig::LIBEVENT_pthreads
    PkgConfig::SYSTEMD
    CURL::libcurl
)

add_executable(firebase-notifier
    firebase.cpp
    google_auth.cpp
)
target_link_libraries(firebase-notifier PRIVATE spns-notifier)
add_executable(apns-notifier
    apns.cpp
    apns_auth.cpp
)
target_link_libraries(apns-notifier PRIVATE spns-notifier)

install(TARGETS firebase-notifier apns-notifier)
