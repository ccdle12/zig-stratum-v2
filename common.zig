const std = @import("std");
const types = @import("types.zig");
const test_util = @import("test_util.zig");

const testing = std.testing;
const expect = testing.expect;
const mem = std.mem;

const serdeTestAlloc = test_util.serdeTestAlloc;
const frameTestAlloc = test_util.frameTestAlloc;
const STR0_255 = types.STR0_255;
const MiningFlags = @import("mining.zig").MiningFlags;
const MessageType = types.MessageType;

/// The CHANNEL_BIT_MASK is used to mask out the MSB to identify if a message
/// type has a channel_id in it's message frame.
pub const CHANNEL_BIT_MASK = 0x8000;

// TODO: Might need to move this to a per message basis.
pub const EXTENSION_TYPE = 0x0000;

/// Initiates the connection. This MUST be the first message sent by the client
/// on the newly opened connection. Server MUST respond with either a
/// SetupConnection.Success or SetupConnection.Error message. Clients that are 
/// not configured to provide telemetry data to the upstream node SHOULD set 
/// device_id to 0-length strings. However, they MUST always set vendor to a 
/// string describing the manufacturer/developer and firmware version and 
/// SHOULD always set hardware_version to a string describing, at least, the 
/// particular hardware/software package in use.
pub fn SetupConnection(comptime T: type) type {
    return struct {
        pub const message_type: MessageType = .SetupConnection;
        const Self = @This();

        /// The minimum protocol version the client supports (currently must be 2).
        min_version: u16,

        /// The maximum protocol version the client supports (currently must be 2).
        max_version: u16,

        /// Flags indicating optional protocol features the client supports. 
        /// Each protocol from protocol field has its own values/flags.
        flags: u32,

        /// ASCII text indicating the hostname or IP address.
        endpoint_host: STR0_255,

        /// Connecting port value.
        endpoint_port: u16,

        /// Used to indicate the vendor/manufacturer of the device. E.g. "Bitmain"
        vendor: STR0_255,

        /// Used to indicate the hardware version of the device. E.g. "S9i 13.5"
        hardware_version: STR0_255,

        /// Used to indicate the firmware on the device. E.g. "braiins-os-2018-09-22-1-hash"
        firmware: STR0_255,

        /// Used to indicate the unique identifier of the device defined by the
        /// vendor.
        device_id: STR0_255,

        pub fn init(
            min_version: u16,
            max_version: u16,
            flags: []const T,
            endpoint_host: []const u8,
            endpoint_port: u16,
            vendor: []const u8,
            hardware_version: []const u8,
            firmware: []const u8,
            device_id: []const u8,
        ) !Self {
            return Self{
                .min_version = min_version,
                .max_version = max_version,
                .flags = MiningFlags.serialize(flags),
                .endpoint_host = try STR0_255.init(endpoint_host),
                .endpoint_port = endpoint_port,
                .vendor = try STR0_255.init(vendor),
                .hardware_version = try STR0_255.init(hardware_version),
                .firmware = try STR0_255.init(firmware),
                .device_id = try STR0_255.init(device_id),
            };
        }

        pub fn msg_len(self: Self) u24 {
            return @sizeOf(u16) +
                @sizeOf(u16) +
                @sizeOf(u32) +
                self.endpoint_host.type_len() +
                @sizeOf(u16) +
                self.vendor.type_len() +
                self.hardware_version.type_len() +
                self.firmware.type_len() +
                self.device_id.type_len();
        }

        pub fn write(self: Self, writer: anytype) !void {
            try writer.writeIntLittle(u16, self.min_version);
            try writer.writeIntLittle(u16, self.max_version);
            try writer.writeIntLittle(u32, self.flags);
            try self.endpoint_host.write(writer);
            try writer.writeIntLittle(u16, self.endpoint_port);
            try self.vendor.write(writer);
            try self.hardware_version.write(writer);
            try self.firmware.write(writer);
            try self.device_id.write(writer);
        }

        pub fn read(gpa: *mem.Allocator, reader: anytype) !Self {
            return Self{
                .min_version = try reader.readIntNative(u16),
                .max_version = try reader.readIntNative(u16),
                .flags = try reader.readIntNative(u32),
                .endpoint_host = try STR0_255.read(gpa, reader),
                .endpoint_port = try reader.readIntNative(u16),
                .vendor = try STR0_255.read(gpa, reader),
                .hardware_version = try STR0_255.read(gpa, reader),
                .firmware = try STR0_255.read(gpa, reader),
                .device_id = try STR0_255.read(gpa, reader),
            };
        }

        pub fn deinit(self: Self, gpa: *mem.Allocator) void {
            self.endpoint_host.deinit(gpa);
            self.vendor.deinit(gpa);
            self.hardware_version.deinit(gpa);
            self.firmware.deinit(gpa);
            self.device_id.deinit(gpa);
        }

        pub fn frame(self: Self, buf: *std.ArrayList(u8)) !void {
            var writer = &buf.writer();
            try writer.writeIntLittle(u16, EXTENSION_TYPE);
            try writer.writeIntLittle(u8, @enumToInt(Self.message_type));
            try writer.writeIntLittle(u24, self.msg_len());
            try self.write(writer);
        }

        pub fn unframe(gpa: *mem.Allocator, reader: anytype) !Self {
            const extension_type = try reader.readIntNative(u16);
            if (extension_type & CHANNEL_BIT_MASK != 0)
                return error.ExpectedChannelBitUnset;

            const msg_type = try reader.readIntNative(u8);
            if (@intToEnum(MessageType, msg_type) != SetupConnection(MiningFlags).message_type)
                return error.InvalidMessageType;

            _ = try reader.readIntNative(u24);

            return read(gpa, reader);
        }

        pub fn eql(self: Self, other: Self) bool {
            if (self.min_version != other.min_version) return false;
            if (self.max_version != other.max_version) return false;
            if (self.flags != other.flags) return false;
            if (!mem.eql(u8, self.endpoint_host.value, other.endpoint_host.value)) return false;
            if (self.endpoint_port != other.endpoint_port) return false;
            if (!mem.eql(u8, self.vendor.value, other.vendor.value)) return false;
            if (!mem.eql(u8, self.firmware.value, other.firmware.value)) return false;
            if (!mem.eql(u8, self.device_id.value, other.device_id.value)) return false;
            return true;
        }
    };
}

test "SetupConnection Mining serialized" {
    const flags = [_]MiningFlags{ .RequiresWorkSelection, .RequiresVersionRolling };
    const before = try SetupConnection(MiningFlags).init(
        2,
        2,
        flags[0..],
        "0.0.0.0",
        8545,
        "Bitmain",
        "S9i 13.5",
        "braiins-os-2018-09-22-1-hash",
        "some-device-uuid",
    );

    const expected = [_]u8{
        0x02, 0x00, // min_version
        0x02, 0x00, // max_version
        0x06, 0x00, 0x00, 0x00, // flags
        0x07, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, // endpoint_host
        0x61, 0x21, // endpoint_port
        0x07, 0x42, 0x69, 0x74, 0x6d, 0x61, 0x69, 0x6e, // vendor
        0x08, 0x53, 0x39, 0x69, 0x20, 0x31, 0x33, 0x2e, 0x35, // hardware_version
        0x1c, 0x62, 0x72, 0x61, 0x69, 0x69, 0x6e, 0x73, 0x2d,
        0x6f, 0x73, 0x2d, 0x32, 0x30, 0x31, 0x38, 0x2d, 0x30,
        0x39, 0x2d, 0x32, 0x32, 0x2d, 0x31, 0x2d, 0x68, 0x61,
        0x73,
        0x68, 0x10, 0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x64, 0x65, // firmware
        0x76, 0x69, 0x63, 0x65, 0x2d, 0x75,
        0x75, 0x69, 0x64, // device_id
    };

    const after = try serdeTestAlloc(SetupConnection(MiningFlags), testing.allocator, before, expected.len, expected);
    defer after.deinit(testing.allocator);

    try expect(before.eql(after));
}

test "SetupConnection Mining frame" {
    const flags = [_]MiningFlags{.RequiresStandardJobs};
    const before = try SetupConnection(MiningFlags).init(
        2,
        2,
        flags[0..],
        "0.0.0.0",
        8545,
        "Bitmain",
        "S9i 13.5",
        "braiins-os-2018-09-22-1-hash",
        "some-device-uuid",
    );

    const expected = [_]u8{
        0x00, 0x00, // extenstion type & channel bit (MSB=0)
        0x00, // message_type
        0x51, 0x00, 0x00, // message_length
    };

    const after = try frameTestAlloc(SetupConnection(MiningFlags), testing.allocator, before, expected.len, expected);
    defer after.deinit(testing.allocator);

    try expect(before.eql(after));
}
