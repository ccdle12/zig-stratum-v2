const std = @import("std");
const codec = @import("codec.zig");
const common = @import("common.zig");
const types = @import("types.zig");
const test_util = @import("test_util.zig");

const testing = std.testing;
const expect = testing.expect;
const mem = std.mem;

const CHANNEL_BIT_MASK = codec.CHANNEL_BIT_MASK;
const MessageType = types.MessageType;
const serdeTestNoAlloc = test_util.serdeTestNoAlloc;
const frameTestNoAlloc = test_util.frameTestNoAlloc;
const U256 = types.U256;
const unframeNoAlloc = codec.unframeNoAlloc;

const Error = error{
    InvalidMessageType,
    InvalidMessageLength,
    ExpectedChannelBitSet,
    ExpectedChannelBitUnset,
};

/// Flags indicating optional protocol features supported by both the client
/// and server.
pub const MiningFlags = enum(u32) {
    RequiresStandardJobs = 1 << 0,
    RequiresWorkSelection = 1 << 1,
    RequiresVersionRolling = 1 << 2,

    /// Convert a slice of MiningFlags variants to its u32 representation of
    /// each corresponding set bit.
    pub fn serialize(flags: []const MiningFlags) u32 {
        var f: u32 = 0;
        for (flags) |flag| f |= @enumToInt(flag);
        return f;
    }

    /// Checks whether a particular flag has its corresponding bit set in a u32
    /// representation.
    pub fn contains(flags: u32, flag: MiningFlags) bool {
        return flags & @enumToInt(flag) != 0;
    }
};

/// UpdateChannel is sent from the Client to a Server. This message is used by
/// the Client to notify the server about specific changes to a channel.
const UpdateChannel = struct {
    pub const message_type: MessageType = .UpdateChannel;
    pub const channel_bit_set = true;
    pub const extension_type = 0x0000;

    /// The unique identifier of the channel.
    channel_id: u32,

    /// The expected [h/s] (hash rate/per second) of the device or the
    /// cumulative rate on the channel if multiple devices are connected
    /// downstream. Proxies MUST send 0.0f when there are no mining devices
    /// connected yet.
    nominal_hash_rate: f32,

    /// The Max Target that can be accepted by the connected device or
    /// multiple devices downstream. In this case, if the max_target of
    /// the channel is smaller than the current max target, the Server MUST
    /// respond with a SetTarget message.
    max_target: U256,

    pub fn init(channel_id: u32, nominal_hash_rate: f32, max_target: U256) UpdateChannel {
        return .{
            .channel_id = channel_id,
            .nominal_hash_rate = nominal_hash_rate,
            .max_target = max_target,
        };
    }

    pub fn msg_len(self: UpdateChannel) u24 {
        return @sizeOf(u32) + @sizeOf(f32) + self.max_target.len;
    }

    pub fn write(self: UpdateChannel, writer: anytype) !void {
        try writer.writeIntLittle(u32, self.channel_id);
        try writer.writeAll(mem.asBytes(&self.nominal_hash_rate));
        try writer.writeAll(&self.max_target);
    }

    pub fn read(reader: anytype) !UpdateChannel {
        const channel_id = try reader.readIntNative(u32);
        const nominal_hash_rate = @bitCast(f32, try reader.readBytesNoEof(4));
        const max_target = try reader.readBytesNoEof(32);

        return UpdateChannel{
            .channel_id = channel_id,
            .nominal_hash_rate = nominal_hash_rate,
            .max_target = max_target,
        };
    }

    pub fn frame(self: UpdateChannel, buf: *std.ArrayList(u8)) !void {
        var writer = &buf.writer();
        try writer.writeIntLittle(u16, UpdateChannel.extension_type | CHANNEL_BIT_MASK);
        try writer.writeIntLittle(u8, @enumToInt(UpdateChannel.message_type));
        try writer.writeIntLittle(u24, self.msg_len());
        try self.write(writer);
    }

    pub fn unframe(reader: anytype) !UpdateChannel {
        return unframeNoAlloc(UpdateChannel, reader);
    }
};

test "MiningFlags contains" {
    const TestCase = struct {
        input: u32,
        flag: MiningFlags,
        expected: bool,
    };

    const test_cases = [_]TestCase{
        .{
            .input = 1 << 0,
            .flag = .RequiresStandardJobs,
            .expected = true,
        },
        .{
            .input = 1 << 1,
            .flag = .RequiresStandardJobs,
            .expected = false,
        },
        .{
            .input = 1 << 1,
            .flag = .RequiresWorkSelection,
            .expected = true,
        },
        .{
            .input = 1 << 2,
            .flag = .RequiresVersionRolling,
            .expected = true,
        },
        .{
            .input = 1 << 1 | 1 << 0,
            .flag = .RequiresWorkSelection,
            .expected = true,
        },
        .{
            .input = 1 << 2 | 1 << 1 | 1 << 0,
            .flag = .RequiresWorkSelection,
            .expected = true,
        },
        .{
            .input = 1 << 2 | 1 << 0,
            .flag = .RequiresWorkSelection,
            .expected = false,
        },
        .{
            .input = 1 << 1 | 1 << 0,
            .flag = .RequiresVersionRolling,
            .expected = false,
        },
    };

    for (test_cases) |case|
        try expect(MiningFlags.contains(case.input, case.flag) == case.expected);
}

test "UpdateChannel serialized" {
    var before = UpdateChannel.init(1, 12.5, [_]u8{0} ** 32);
    const expected = [_]u8{
        0x01, 0x00, 0x00, 0x00, // channel_id
        0x00, 0x00, 0x48, 0x41, // nominal_hash_rate
        0x00, 0x00, 0x00, 0x00, // max_target
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    const after = try serdeTestNoAlloc(UpdateChannel, before, expected.len, expected);
    try testing.expectEqual(before, after);
}

test "UpdateChannel frame" {
    const before = UpdateChannel.init(1, 12.5, [_]u8{0} ** 32);
    const expected = [_]u8{
        0x00, 0x80, // extenstion type & channel bit (MSB=1)
        0x16, // message_type
        0x28, 0x00, 0x00, // message_length
    };

    const after = try frameTestNoAlloc(UpdateChannel, before, expected.len, expected);
    try testing.expectEqual(before, after);
}
