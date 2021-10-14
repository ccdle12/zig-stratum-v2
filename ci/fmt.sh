#!/usr/bin/env bash

set -e

zig fmt --check ./messages/*.zig
zig fmt --check ./*.zig
