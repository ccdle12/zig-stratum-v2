#!/usr/bin/env bash

set -e

zig test ./messages/common.zig --main-pkg-path ./
zig test ./messages/mining.zig --main-pkg-path ./
zig test ./messages/types.zig --main-pkg-path ./
zig test ./noise.zig --main-pkg-path ./
