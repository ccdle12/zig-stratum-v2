const std = @import("std");
const types = @import("types.zig");

const assert = std.debug.assert;
const mem = std.mem;

const MessageType = types.MessageType;

/// The CHANNEL_BIT_MASK is used to mask out the MSB to identify if a message
/// type has a channel_id in its message frame.
pub const CHANNEL_BIT_MASK = 0x8000;

pub fn unframeNoAlloc(
    comptime T: type,
    reader: anytype,
) !T {
    comptime assert(@TypeOf(T.channel_bit_set) == bool);
    try unframe(T, T.channel_bit_set, reader);
    return T.read(reader);
}

pub fn unframeAlloc(
    comptime T: type,
    gpa: *mem.Allocator,
    reader: anytype,
) !T {
    comptime assert(@TypeOf(T.channel_bit_set) == bool);
    try unframe(T, T.channel_bit_set, reader);
    return T.read(gpa, reader);
}

fn unframe(
    comptime T: type,
    channel_bit_set: bool,
    reader: anytype,
) !void {
    const extension_type = try reader.readIntNative(u16);

    if (channel_bit_set) {
        if (extension_type & CHANNEL_BIT_MASK == 0)
            return error.ExpectedChannelBitSet;
    } else {
        if (extension_type & CHANNEL_BIT_MASK != 0)
            return error.ExpectedChannelBitUnset;
    }

    const msg_type = try reader.readIntNative(u8);
    if (@intToEnum(MessageType, msg_type) != T.message_type)
        return error.InvalidMessageType;

    const len = try reader.readIntNative(u24);
    _ = len;
}
