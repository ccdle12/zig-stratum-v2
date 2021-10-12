const std = @import("std");

const testing = std.testing;
const expect = testing.expect;
const mem = std.mem;
const io = std.io;

/// De/serialization test helper for StratumV2 messages.
pub fn serdeTestNoAlloc(
    comptime T: type,
    before: T,
    comptime size: comptime_int,
    expected: [size]u8,
) !T {
    const buf = try serdeTest(T, before, size, expected);
    defer buf.deinit();
    return try T.read(io.fixedBufferStream(buf.items).reader());
}

pub fn serdeTestAlloc(
    comptime T: type,
    gpa: *mem.Allocator,
    before: T,
    comptime size: comptime_int,
    expected: [size]u8,
) !T {
    const buf = try serdeTest(T, before, size, expected);
    defer buf.deinit();
    return try T.read(gpa, io.fixedBufferStream(buf.items).reader());
}

fn serdeTest(
    comptime T: type,
    before: T,
    comptime size: comptime_int,
    expected: [size]u8,
) !std.ArrayList(u8) {
    var buf = std.ArrayList(u8).init(testing.allocator);

    try before.write(buf.writer());
    try expect(mem.eql(u8, buf.items, &expected));

    return buf;
}

/// Un/frame test helper for StratumV2 messages.
pub fn frameTestNoAlloc(
    comptime T: type,
    before: T,
    comptime size: comptime_int,
    expected: [size]u8,
) !T {
    const buf = try frameTest(T, before, size, expected);
    defer buf.deinit();
    return try T.unframe(io.fixedBufferStream(buf.items).reader());
}

pub fn frameTestAlloc(
    comptime T: type,
    gpa: *mem.Allocator,
    before: T,
    comptime size: comptime_int,
    expected: [size]u8,
) !T {
    const buf = try frameTest(T, before, size, expected);
    defer buf.deinit();
    return try T.unframe(gpa, io.fixedBufferStream(buf.items).reader());
}

fn frameTest(
    comptime T: type,
    before: T,
    comptime size: comptime_int,
    expected: [size]u8,
) !std.ArrayList(u8) {
    var buf = std.ArrayList(u8).init(testing.allocator);

    try before.frame(buf.writer());
    try expect(mem.eql(u8, buf.items[0..6], &expected));

    return buf;
}
