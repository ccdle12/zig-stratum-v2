const std = @import("std");
const test_util = @import("test_util.zig");

const testing = std.testing;
const expect = testing.expect;
const mem = std.mem;
const serdeTestAlloc = test_util.serdeTestAlloc;

pub const U256 = [32]u8;

const Error = error{
    InvalidStrLength,
};

/// MessageType contains all the byte codes for each StratumV2 message.
pub const MessageType = enum(u8) {
    SetupConnection = 0x00,
    UpdateChannel = 0x16,
};

pub const STR0_255 = struct {
    value: []const u8,

    pub fn init(str: []const u8) !STR0_255 {
        if (str.len > 255) return error.InvalidStrLength;
        return STR0_255{ .value = str };
    }

    pub fn type_len(self: STR0_255) u8 {
        return @sizeOf(u8) + @intCast(u8, self.value.len);
    }

    pub fn write(self: STR0_255, buf: *std.ArrayList(u8)) !void {
        var writer = &buf.writer();
        try writer.writeIntLittle(u8, @intCast(u8, self.value.len));
        try writer.writeAll(self.value);
    }

    pub fn read(gpa: *mem.Allocator, reader: anytype) !STR0_255 {
        const len = try reader.readByte();

        var buf: [255]u8 = undefined;
        _ = try reader.read(buf[0..len]);

        const str = try gpa.alloc(u8, len);
        mem.copy(u8, str, buf[0..len]);

        return STR0_255{ .value = str };
    }

    pub fn deinit(self: STR0_255, gpa: *mem.Allocator) void {
        gpa.free(self.value);
    }
};

test "STR0_255 init" {
    const str = try STR0_255.init("hello");
    try expect(mem.eql(u8, str.value, "hello"));
}

test "STR0_255 invalid length" {
    const str = STR0_255.init("e" ** 256);
    try testing.expectError(error.InvalidStrLength, str);
}

test "STR0_255 serialized" {
    const before = try STR0_255.init("e" ** 10);

    const len = [_]u8{0x0A};
    const value = [_]u8{0x65} ** 10;
    const expected = len ++ value;

    const after = try serdeTestAlloc(STR0_255, testing.allocator, before, expected.len, expected);
    defer after.deinit(testing.allocator);

    try expect(mem.eql(u8, before.value, after.value));
}
