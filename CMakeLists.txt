cmake_minimum_required(VERSION 3.13...3.31)

project(spns-firebase
    VERSION 2.0.0
    DESCRIPTION "Session Push Notification Server - Google Firebase notifier"
    LANGUAGES C CXX)

find_package(pybind11 REQUIRED)
find_package(CURL REQUIRED COMPONENTS HTTPS SSL HTTP2)
find_package(PkgConfig REQUIRED)

pkg_check_modules(OMQ REQUIRED IMPORTED_TARGET liboxenmq>=1.2.22)
pkg_check_modules(OXENLOGGING REQUIRED IMPORTED_TARGET liboxen-logging>=1.2)
pkg_check_modules(CLI11 REQUIRED IMPORTED_TARGET CLI11>=2.1)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)
pkg_check_modules(OXENC REQUIRED IMPORTED_TARGET liboxenc>=1.4)
pkg_check_modules(FMT REQUIRED IMPORTED_TARGET fmt>=10)
pkg_check_modules(QUIC REQUIRED IMPORTED_TARGET liboxenquic>=1.5)
pkg_check_modules(LIBEVENT_core libevent_core>=2.1 IMPORTED_TARGET REQUIRED)
pkg_check_modules(LIBEVENT_pthreads libevent_pthreads>=2.1 IMPORTED_TARGET REQUIRED)

add_executable(firebase-notifier
    firebase-notifier.cpp

    google_auth.cpp
    http2_notifier.cpp
    notification.cpp
    util.cpp
)

target_compile_features(firebase-notifier PUBLIC cxx_std_20)

target_link_libraries(firebase-notifier
    PUBLIC
    pybind11::embed
    PkgConfig::OMQ
    PkgConfig::OXENLOGGING
    PkgConfig::CLI11
    PkgConfig::FMT
    PkgConfig::OXENC
    PkgConfig::SODIUM
    PkgConfig::QUIC
    PkgConfig::LIBEVENT_core
    PkgConfig::LIBEVENT_pthreads
    CURL::libcurl
)
