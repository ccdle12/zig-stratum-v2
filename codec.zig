const std = @import("std");
const types = @import("./messages/types.zig");

const assert = std.debug.assert;
const mem = std.mem;

const MessageType = types.MessageType;

/// The CHANNEL_BIT_MASK is used to mask out the MSB to identify if a message
/// type has a channel_id in its message frame.
pub const CHANNEL_BIT_MASK = 0x8000;

const Error = error{
    InvalidMessageType,
    InvalidMessageLength,
    ExpectedChannelBitSet,
    ExpectedChannelBitUnset,
};

pub fn unframeNoAlloc(
    comptime T: type,
    reader: anytype,
) !T {
    try unframe(T, reader);
    return T.read(reader);
}

pub fn unframeAlloc(
    comptime T: type,
    gpa: *mem.Allocator,
    reader: anytype,
) !T {
    try unframe(T, reader);
    return T.read(gpa, reader);
}

fn unframe(
    comptime T: type,
    reader: anytype,
) !void {
    MessageType.assertInvariants(T);

    const extension_type = try reader.readIntNative(u16);
    if (T.channel_bit_set) {
        if (extension_type & CHANNEL_BIT_MASK == 0) return error.ExpectedChannelBitSet;
    } else {
        if (extension_type & CHANNEL_BIT_MASK != 0) return error.ExpectedChannelBitUnset;
    }

    const msg_type = try reader.readIntNative(u8);
    if (@intToEnum(MessageType, msg_type) != T.message_type)
        return error.InvalidMessageType;

    const len = try reader.readIntNative(u24);
    _ = len;
}

pub fn frame(
    comptime T: type,
    msg: T,
    writer: anytype,
) !void {
    MessageType.assertInvariants(T);

    var extension_type = T.extension_type;
    if (T.channel_bit_set) extension_type |= CHANNEL_BIT_MASK;

    try writer.writeIntLittle(u16, extension_type);
    try writer.writeIntLittle(u8, @enumToInt(T.message_type));
    try writer.writeIntLittle(u24, msg.msg_len());
    try msg.write(writer);
}
