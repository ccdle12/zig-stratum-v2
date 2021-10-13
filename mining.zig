const std = @import("std");
const codec = @import("codec.zig");
const types = @import("types.zig");
const test_util = @import("test_util.zig");

const testing = std.testing;
const expect = testing.expect;
const mem = std.mem;

const check_message_invariants = types.check_message_invariants;
const MessageType = types.MessageType;
const serdeTestNoAlloc = test_util.serdeTestNoAlloc;
const frameTestNoAlloc = test_util.frameTestNoAlloc;
const U256 = types.U256;

pub const MiningFlags = enum(u32) {
    RequiresStandardJobs = 1 << 0,
    RequiresWorkSelection = 1 << 1,
    RequiresVersionRolling = 1 << 2,

    pub usingnamespace FlagMixin(MiningFlags);
};

pub const MiningFlagsSuccess = enum(u32) {
    RequiresFixedVersion = 1 << 0,
    RequiresExtendedChannels = 1 << 1,

    pub usingnamespace FlagMixin(MiningFlagsSuccess);
};

fn FlagMixin(comptime T: type) type {
    return struct {
        pub fn serialize(flags: []const T) u32 {
            var f: u32 = 0;
            for (flags) |flag| f |= @enumToInt(flag);
            return f;
        }

        pub fn contains(flags: u32, flag: T) bool {
            return flags & @enumToInt(flag) != 0;
        }
    };
}

pub const UpdateChannel = struct {
    pub const message_type: MessageType = .UpdateChannel;
    pub const channel_bit_set = true;
    pub const extension_type: u16 = 0x0000;

    channel_id: u32,
    nominal_hash_rate: f32,
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

    pub fn frame(self: UpdateChannel, writer: anytype) !void {
        try codec.frame(UpdateChannel, self, writer);
    }

    pub fn unframe(reader: anytype) !UpdateChannel {
        return codec.unframeNoAlloc(UpdateChannel, reader);
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

test "UpdateChannel message invariants" {
    check_message_invariants(UpdateChannel);
}

test "UpdateChannel serialize" {
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
