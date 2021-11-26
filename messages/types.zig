const std = @import("std");
const test_util = @import("test_util.zig");

const assert = std.debug.assert;
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
    SetupConnectionSuccess = 0x01,
    SetupConnectionError = 0x02,
    ChannelEndpointChanged = 0x03,
    UpdateChannel = 0x16,

    /// Checks whether T (assumed to be a StratumV2 message) contains the required
    /// invariants.
    pub fn assertInvariants(comptime T: type) void {
        comptime {
            assert(!@hasField(T, "channel_bit_set"));
            assert(@TypeOf(T.channel_bit_set) == bool);

            assert(!@hasField(T, "message_type"));
            assert(@TypeOf(T.message_type) == MessageType);

            assert(!@hasField(T, "extension_type"));
            assert(@TypeOf(T.extension_type) == u16);
        }
    }
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

    pub fn write(self: STR0_255, writer: anytype) !void {
        try writer.writeIntLittle(u8, @intCast(u8, self.value.len));
        try writer.writeAll(self.value);
    }

    pub fn read(gpa: *mem.Allocator, reader: anytype) !STR0_255 {
        const len = try reader.readByte();
        const str = try gpa.alloc(u8, len);
        _ = try reader.read(str);

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

    const after = try serdeTestAlloc(
        STR0_255,
        testing.allocator,
        before,
        expected.len,
        expected,
    );
    defer after.deinit(testing.allocator);

    try expect(mem.eql(u8, before.value, after.value));
}
