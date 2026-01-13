# Session Push Notification Server - Firebase/APNs notifiers

This code contains the Firebase and APNs notifier plugin for the [Session Push Notification
Server](https://github.com/session-foundation/session-push-notification-server) that allows the SPNS
to interface with FCM servers (for Google) and APNs servers (for Apple) to deliver Android and Apple
push notifications via HTTP2 requests over long-lived HTTP2 connections to their respective servers.

The code is written in C++ with various dependencies Session project and other external dependencies
(see `CMakeLists.txt`).
