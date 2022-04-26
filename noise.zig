const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

const mem = std.mem;
const expect = testing.expect;
const Ed25519 = crypto.sign.Ed25519;
const Hmac = std.crypto.auth.hmac.Hmac;
const X25519 = crypto.dh.X25519;
const Blake2s256 = crypto.hash.blake2.Blake2s256;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

const blake_hmac = Hmac(Blake2s256);
const encrypt = ChaCha20Poly1305.encrypt;
const decrypt = ChaCha20Poly1305.decrypt;

pub const hash_len = 32;
pub const key_len = 32;
pub const block_len = 64;
pub const mac_len = 16;
pub const max_msg_len = 65535;

pub const empty_key = [_]u8{0} ** 32;
pub const empty_hash = [_]u8{0} ** 32;

inline fn is_empty_key(key: *[32]u8) bool {
    return mem.eql(u8, key, &empty_key);
}

const Error = error{
    EndOfBuffer,
};

/// A NoiseSession contains the full behaviour and state to setup and perform
/// secure communication. This uses the described pattern (Noise_NX), as suggested 
/// in the StratumV2 spec:
/// https://docs.google.com/document/d/1FadCWj-57dvhxsnFM_7X806qyvhR0u3i85607bGHxvg/edit#heading=h.67e0xwyzxi0u
pub const NoiseSession = struct {
    /// SessionState indicates the current stage of the Noise handshake.
    state: SessionState,
    // TODO: Doc comment on the handshake state
    hs: HandshakeState,
    // TODO: Doc comment h
    h: [hash_len]u8,
    // TODO: Doc comment cs1
    cs1: CipherState,
    // TODO: Doc comment cs2
    cs2: CipherState,
    // TODO: Doc comment mc
    mc: u128,
    is_initiator: bool,

    pub const SessionState = enum {
        /// E indicates a state where the ephemeral key (self.hs.e) is generated
        /// and will be sent/received over the wire in an ephemeral key exchange.
        E,
        /// ES indicates that the ephemeral key (self.hs.e) has been sent and a
        /// cipher text of each static key will be exchanged. Once the static keys
        /// have been received and decrypted, a CipherState will be generated for
        /// both parties and secure communication can commence.
        ES,
        /// T indicates a transport state, the handshakes have been completed
        /// and both parties can communicate securely.
        T,
    };

    /// Constructor for the initiator of a NoiseSession.
    pub fn initiator(prologue: []const u8, s: Ed25519.KeyPair) NoiseSession {
        return init(prologue, s, true);
    }

    /// Constructor for the responder of a NoiseSession.
    pub fn responder(prologue: []const u8, s: Ed25519.KeyPair) NoiseSession {
        return init(prologue, s, false);
    }

    fn init(prologue: []const u8, s: Ed25519.KeyPair, is_initiator: bool) NoiseSession {
        return .{
            .state = .E,
            .hs = HandshakeState.init(is_initiator, prologue, s, empty_key),
            .h = empty_hash,
            .cs1 = CipherState.init(),
            .cs2 = CipherState.init(),
            .mc = 0,
            .is_initiator = is_initiator,
        };
    }

    pub fn send_msg(self: *NoiseSession, msg: []u8) !void {
        if (msg.len < mac_len or msg.len > max_msg_len)
            return error.EndOfBuffer;

        try self.process_msg(msg, true);
        self.mc += 1;
    }

    pub fn read_msg(self: *NoiseSession, msg: []u8) !void {
        if (msg.len < mac_len or msg.len > max_msg_len)
            return error.EndOfBuffer;

        try self.process_msg(msg, false);
        self.mc += 1;
    }

    fn process_msg(self: *NoiseSession, msg: []u8, send: bool) !void {
        switch (self.state) {
            .E => {
                switch (send) {
                    true => try self.hs.write_msg_e(msg),
                    else => try self.hs.read_msg_e(msg),
                }
                self.state = .ES;
            },
            .ES => {
                const cipher_state = blk: {
                    break :blk switch (send) {
                        true => try self.hs.write_msg_es(msg),
                        else => try self.hs.read_msg_es(msg),
                    };
                };
                self.h = cipher_state.hash;
                self.cs1 = cipher_state.cs1;
                self.cs2 = cipher_state.cs2;
                self.hs.clear();
                self.state = .T;
            },
            .T => {
                switch (send) {
                    true => switch (self.is_initiator) {
                        true => self.cs1.write_msg_transport(msg),
                        else => self.cs2.write_msg_transport(msg),
                    },
                    else => switch (self.is_initiator) {
                        true => try self.cs2.read_msg_transport(msg),
                        else => try self.cs1.read_msg_transport(msg),
                    },
                }
            },
        }
    }

    pub fn is_transport(self: NoiseSession) bool {
        return self.state == .T;
    }
};

pub const HandshakeState = struct {
    ss: SymmetricState,

    /// The local static keypair.
    s: ?Ed25519.KeyPair,

    /// The local ephemeral keypair.
    e: ?Ed25519.KeyPair,

    /// The remote parties static public key.
    rs: [key_len]u8,

    /// The remote parties ephemeral public key.
    re: [key_len]u8,

    /// Indicates the initiator or responder role.
    initiator: bool,

    /// Pre-shared Secret Key.
    psk: [key_len]u8,

    pub fn clear(self: *HandshakeState) void {
        self.s = null;
        self.e = null;
        self.re = empty_key;
        self.psk = empty_key;
    }

    pub fn init(
        initiator: bool,
        prologue: []const u8,
        s: Ed25519.KeyPair,
        psk: [key_len]u8,
    ) HandshakeState {
        const protocol_name = "Noise_NX_25519_ChaChaPoly_BLAKE2s";
        var ss = SymmetricState.initialize_symmetric(protocol_name);
        ss.mix_hash(prologue);

        return .{
            .ss = ss,
            .s = s,
            .e = null,
            .rs = empty_key,
            .re = empty_key,
            .initiator = initiator,
            .psk = psk,
        };
    }

    pub fn write_msg_e(self: *HandshakeState, msg: []u8) !void {
        if (msg.len < key_len)
            return error.EndOfBuffer;

        if (self.e == null)
            self.e = try Ed25519.KeyPair.create(null);

        mem.copy(u8, msg[0..key_len], &self.e.?.public_key);
        self.ss.mix_hash(msg[0..key_len]);
        self.ss.mix_hash(msg[key_len..]);
    }

    pub const CipherStateResult = struct {
        hash: [hash_len]u8,
        cs1: CipherState,
        cs2: CipherState,
    };

    pub fn write_msg_es(self: *HandshakeState, msg: []u8) !CipherStateResult {
        if (msg.len < key_len)
            return error.EndOfBuffer;

        if (self.e == null)
            self.e = try Ed25519.KeyPair.create(null);

        mem.copy(u8, msg[0..key_len], &self.e.?.public_key);
        self.ss.mix_hash(msg[0..key_len]);
        self.ss.mix_key(&try dh(self.e.?, self.re));

        var ns = msg[key_len .. (key_len * 2) + mac_len];
        mem.copy(u8, ns, &self.s.?.public_key);
        try self.ss.encrypt_and_hash(ns);

        self.ss.mix_key(&try dh(self.s.?, self.re));
        try self.ss.encrypt_and_hash(msg[(key_len * 2) + mac_len ..]);

        const cs = self.ss.split();
        self.ss.clear();

        return CipherStateResult{
            .hash = self.ss.h,
            .cs1 = cs[0],
            .cs2 = cs[1],
        };
    }

    pub fn read_msg_e(self: *HandshakeState, msg: []u8) !void {
        if (msg.len < key_len + mac_len)
            return error.EndOfBuffer;

        mem.copy(u8, &self.re, msg[0..key_len]);
        self.ss.mix_hash(&self.re);
        self.ss.mix_hash(msg[key_len..]);
    }

    pub fn read_msg_es(self: *HandshakeState, msg: []u8) !CipherStateResult {
        if (msg.len < mac_len + key_len)
            return error.EndOfBuffer;

        mem.copy(u8, &self.re, msg[0..key_len]);
        self.ss.mix_hash(&self.re);
        self.ss.mix_key(&try dh(self.e.?, self.re));

        var rs = msg[key_len .. (key_len * 2) + mac_len];
        try self.ss.decrypt_and_hash(rs);
        mem.copy(u8, &self.rs, rs[0..key_len]);
        self.ss.mix_key(&try dh(self.e.?, self.rs));

        try self.ss.decrypt_and_hash(msg[(key_len * 2) + mac_len ..]);

        const cs = self.ss.split();
        self.ss.clear();

        return CipherStateResult{
            .hash = self.ss.h,
            .cs1 = cs[0],
            .cs2 = cs[1],
        };
    }

    fn dh(secret_keypair: Ed25519.KeyPair, key: [key_len]u8) ![key_len]u8 {
        const s = try X25519.KeyPair.fromEd25519(secret_keypair);
        const p = try X25519.publicKeyFromEd25519(key);
        return try X25519.scalarmult(s.secret_key, p);
    }
};

// Contains the CipherState, plus ck and h variables. During the handshake phase
// each party has a single SymmetricState which can be deleted once the handshake
// completes_h.
pub const SymmetricState = struct {
    cs: CipherState,

    // The Chaining Key of the cipher state.
    ck: [key_len]u8,
    h: [hash_len]u8,

    pub fn initialize_symmetric(protocol_name: []const u8) SymmetricState {
        var hash: [hash_len]u8 = undefined;

        var h = Blake2s256.init(.{});
        h.update(protocol_name);
        h.final(&hash);

        var ck: [key_len]u8 = undefined;
        mem.copy(u8, &ck, &hash);

        return .{
            .cs = CipherState.init(),
            .ck = ck,
            .h = hash,
        };
    }

    pub fn mix_hash(self: *SymmetricState, data: []const u8) void {
        var hash: [hash_len]u8 = undefined;

        var h = Blake2s256.init(.{});
        h.update(&self.h);
        h.update(data);
        h.final(&hash);

        self.h = hash;
    }

    pub fn mix_key(self: *SymmetricState, input_key_material: []u8) void {
        var out0 = empty_hash;
        var out1 = empty_hash;
        var out2 = empty_hash;

        hkdf(
            &self.ck,
            input_key_material,
            2,
            &out0,
            &out1,
            &out2,
        );

        self.ck = out0;

        var key = empty_key;
        mem.copy(u8, &key, &out1);
        self.cs = CipherState.from_key(key);
    }

    pub fn encrypt_and_hash(self: *SymmetricState, msg: []u8) !void {
        // TODO: Check for under/overflow bug
        var mac: [mac_len]u8 = undefined;
        self.cs.encrypt_with_ad(&self.h, msg[0 .. msg.len - mac_len], &mac);

        mem.copy(u8, msg[msg.len - mac_len ..], &mac);
        self.mix_hash(msg);
    }

    pub fn decrypt_and_hash(self: *SymmetricState, msg: []u8) !void {
        var cipher_text: [2048]u8 = undefined;
        mem.copy(u8, cipher_text[0..msg.len], msg);

        var mac: [mac_len]u8 = undefined;
        mem.copy(u8, &mac, msg[msg.len - mac_len ..]);

        try self.cs.decrypt_with_ad(&self.h, msg[0 .. msg.len - mac_len], mac);
        self.mix_hash(cipher_text[0..msg.len]);
    }

    pub fn split(self: SymmetricState) [2]CipherState {
        var send_key = empty_key;
        var recv_key = empty_key;
        var out2 = empty_hash;

        hkdf(
            &self.ck,
            &[0]u8{},
            2,
            &send_key,
            &recv_key,
            &out2,
        );

        return .{
            CipherState.from_key(send_key),
            CipherState.from_key(recv_key),
        };
    }

    pub fn clear(self: *SymmetricState) void {
        self.cs.k = empty_key;
        self.ck = empty_key;
    }
};

// During the handshake phase each party has a single CipherState but during
// the transport phase each party has two CipherState objects: one for sending
// and one for receiving.
pub const CipherState = struct {
    // A cipher key of 32 bytes (which maybe empty).
    k: [key_len]u8,

    // An 8-byte unsigned integer nonce.
    n: u64,

    pub fn init() CipherState {
        return .{
            .k = empty_key,
            .n = 0,
        };
    }

    pub fn from_key(key: [key_len]u8) CipherState {
        return .{
            .k = key,
            .n = 0,
        };
    }

    pub fn encrypt_with_ad(
        self: *CipherState,
        ad: []const u8,
        msg: []u8,
        mac: *[mac_len]u8,
    ) void {
        if (!is_empty_key(&self.k)) {
            encrypt(msg, mac, msg, ad, nonce_to_bytes(self.n), self.k);
            self.n += 1;
        }
    }

    pub fn decrypt_with_ad(
        self: *CipherState,
        ad: []const u8,
        msg: []u8,
        mac: [mac_len]u8,
    ) !void {
        if (!is_empty_key(&self.k)) {
            try decrypt(msg, msg, mac, ad, nonce_to_bytes(self.n), self.k);
            self.n += 1;
        }
    }

    pub fn write_msg_transport(self: *CipherState, msg: []u8) void {
        var mac: [mac_len]u8 = undefined;
        self.encrypt_with_ad(&[0]u8{}, msg[0 .. msg.len - mac_len], &mac);
        mem.copy(u8, msg[msg.len - mac_len ..], &mac);
    }

    pub fn read_msg_transport(self: *CipherState, msg: []u8) !void {
        var mac: [mac_len]u8 = undefined;
        mem.copy(u8, &mac, msg[msg.len - mac_len ..]);
        try self.decrypt_with_ad(&[0]u8{}, msg[0 .. msg.len - mac_len], mac);
    }
};

fn nonce_to_bytes(nonce: u64) [12]u8 {
    var buffer = [_]u8{0} ** 12;
    mem.writeIntLittle(u64, &buffer[4..][0..8].*, nonce);
    return buffer;
}

inline fn hmac(key: *const [hash_len]u8, data: []const u8, out: *[hash_len]u8) void {
    var h = blake_hmac.init(key);
    h.update(data);
    h.final(out);
}

pub fn hkdf(
    chaining_key: *const [hash_len]u8,
    input_key_material: []const u8,
    outputs: usize,
    out1: *[hash_len]u8,
    out2: *[hash_len]u8,
    out3: *[hash_len]u8,
) void {
    var key = empty_key;
    hmac(chaining_key, input_key_material, &key);
    hmac(&key, &[_]u8{1}, out1);
    if (outputs == 1) return;

    var in2: [hash_len + 1]u8 = undefined;
    mem.copy(u8, &in2, out1);

    in2[hash_len] = 2;
    hmac(&key, &in2, out2);
    if (outputs == 2) return;

    var in3: [hash_len + 1]u8 = undefined;
    mem.copy(u8, &in3, out2);
    in3[hash_len] = 3;
    hmac(&key, &in3, out3);
}

test "full handshake" {
    var responder = NoiseSession.responder("", try Ed25519.KeyPair.create(null));
    var initiator = NoiseSession.initiator("", try Ed25519.KeyPair.create(null));

    var buf: [1024]u8 = undefined;

    // -> e
    try initiator.send_msg(&buf);
    try responder.read_msg(&buf);

    try expect(initiator.mc == 1 and responder.mc == 1);
    try expect(mem.eql(u8, &initiator.hs.ss.h, &responder.hs.ss.h));

    // <- e..
    try responder.send_msg(&buf);
    try initiator.read_msg(&buf);

    try expect(responder.mc == 2 and initiator.mc == 2);
    try expect(responder.is_transport() and initiator.is_transport());
    try expect(mem.eql(u8, &initiator.hs.ss.h, &responder.hs.ss.h));

    var frame: [1024]u8 = undefined;
    var msg = [_]u8{2} ** 200;
    mem.copy(u8, &frame, &msg);

    // Send, encrypt and decrypt a message from the initiator.
    try initiator.send_msg(&frame);
    try expect(!mem.eql(u8, frame[0..msg.len], &msg));

    try responder.read_msg(&frame);
    try expect(mem.eql(u8, frame[0..msg.len], &msg));

    // Send, encrypt and decrypt a message from the responder to initiator.
    try responder.send_msg(&frame);
    try expect(!mem.eql(u8, frame[0..msg.len], &msg));

    try initiator.read_msg(&frame);
    try expect(mem.eql(u8, frame[0..msg.len], &msg));
}

test "HandshakeState initiator" {
    const secret_key = [_]u8{
        0xd5, 0x42, 0x38, 0x34, 0x95, 0xac, 0xf3, 0x9e, 0x95, 0x07, 0xf9, 0xe8, 0x59, 0x76, //secret
        0xea, 0xd4, 0x27, 0xf3, 0x0a, 0x1e, 0xd5, 0x2c, 0x56, 0x56, 0x33, 0x06, 0x35, 0x2c,
        0x85, 0x88, 0x54, 0xdd,
        0x7b, 0x4e, 0xb7, 0x9a, 0xa6, 0xdc, 0xce, 0x98, 0xa8, 0x7a, 0xcf, 0xf9, 0xc5, 0x9c, // public
        0xcf, 0xbc, 0xca, 0x62, 0x46, 0x95, 0x0a, 0x25, 0x5e, 0x7b, 0x5a, 0xfc, 0xc4, 0x8e,
        0x64, 0x2f, 0x25, 0x27,
    };
    const s = Ed25519.KeyPair.fromSecretKey(secret_key);

    var handshake_state = HandshakeState.init(true, "", s, empty_key);
    const expected_h = [_]u8{
        0xb3, 0xf9, 0xe9, 0x6b, 0x14, 0x94, 0xc2, 0xe5, 0x52, 0xae, 0x50, 0x97,
        0x70, 0x9c, 0x09, 0x5a, 0x37, 0x9e, 0xd4, 0xe0, 0xa1, 0x2f, 0x56, 0xf1,
        0xa4, 0x8f, 0x14, 0x98, 0xc2, 0xbb, 0x6d, 0x6d,
    };
    try expect(mem.eql(u8, &handshake_state.ss.h, &expected_h));

    const expected_ck = [_]u8{
        0x92, 0x27, 0xce, 0x1a, 0x77, 0x03, 0x3d, 0xf3, 0xf2, 0x4c, 0xd1, 0x92,
        0xc1, 0x9c, 0x0b, 0xbe, 0xa8, 0xd5, 0xd7, 0x0a, 0x36, 0xc4, 0x83, 0x7f,
        0xdc, 0x6f, 0xf1, 0x41, 0x8f, 0x04, 0xb4, 0x25,
    };
    try expect(mem.eql(u8, &handshake_state.ss.ck, &expected_ck));
    try expect(handshake_state.e == null);
}

test "nonce to bytes" {
    // TODO: Make a test_utils generic for TestCase
    const TestCase = struct {
        in: u64,
        expected: [12]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .in = 0,
            .expected = [_]u8{0} ** 12,
        },
        .{
            .in = 1,
            .expected = [_]u8{ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
        },
        .{
            .in = 18446744073709551615,
            .expected = [_]u8{ 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 },
        },
    };
    for (test_cases) |c| try expect(mem.eql(u8, &nonce_to_bytes(c.in), &c.expected));
}

test "hmac" {
    var out = empty_key;
    var key = [_]u8{1} ** key_len;
    var data = [_]u8{1} ** key_len;

    hmac(&key, &data, &out);

    const expected = [_]u8{
        0xda, 0x07, 0xb0, 0x8b, 0xcd, 0x74, 0xed, 0xbe, 0x5a,
        0x72, 0xa1, 0xd4, 0x12, 0xfd, 0x5,  0xb5, 0x21, 0xd7,
        0x70, 0x5a, 0xd4, 0x16, 0xf,  0x2a, 0x4d, 0xf3, 0xa9,
        0xb0, 0x4e, 0x4c, 0x57, 0x54,
    };
    try expect(mem.eql(u8, &out, &expected));
}

test "hkdf" {
    const chaining_key = [_]u8{
        0x54, 0x12, 0x07, 0x46, 0xE8, 0xE3, 0x63, 0x64, 0x6B, 0x9F, 0x5D, 0xF8,
        0xF2, 0xE0, 0x30, 0xC4, 0x7C, 0x2A, 0x6C, 0xC0, 0xB5, 0x52, 0x28, 0x04,
        0xFD, 0x9C, 0x71, 0x6B, 0xB9, 0x26, 0x21, 0x09,
    };

    var input_key_material = [_]u8{1} ** key_len;
    var out1 = empty_hash;
    var out2 = empty_hash;
    var out3 = empty_hash;

    hkdf(
        &chaining_key,
        &input_key_material,
        3,
        &out1,
        &out2,
        &out3,
    );

    const TestCase = struct {
        in: [key_len]u8,
        expected: [key_len]u8,
    };

    const test_cases = [_]TestCase{
        .{
            .in = out1,
            .expected = [_]u8{
                0x30, 0x13, 0xFD, 0x21, 0xAD, 0xAC, 0x37, 0xE2, 0xB6, 0x88, 0x51,
                0x0D, 0xFE, 0x4E, 0xB5, 0x22, 0xE5, 0x1A, 0xAF, 0xE6, 0x82, 0xFC,
                0x21, 0x42, 0x9B, 0x6A, 0x21, 0x44, 0xBB, 0xE1, 0x03, 0x4E,
            },
        },
        .{
            .in = out2,
            .expected = [_]u8{
                0x3F, 0xAF, 0x9C, 0x37, 0xD4, 0xAB, 0x5B, 0xD7, 0x62, 0x1D, 0x37,
                0x50, 0x06, 0x11, 0xE7, 0x2D, 0x50, 0xB9, 0x3D, 0x1C, 0x77, 0xFB,
                0x05, 0x39, 0xD9, 0xBD, 0x52, 0xB8, 0xD5, 0xB3, 0xC8, 0x9C,
            },
        },
        .{
            .in = out3,
            .expected = [_]u8{
                0x5A, 0xB3, 0xAA, 0x99, 0xF5, 0x31, 0xA7, 0x06, 0x35, 0x91, 0xEC,
                0xE8, 0x4C, 0x26, 0xD8, 0xC5, 0xD7, 0xD6, 0x3A, 0x2C, 0xCE, 0x11,
                0x5B, 0x5B, 0xAB, 0x60, 0x2C, 0x66, 0x34, 0x34, 0x37, 0x77,
            },
        },
    };

    for (test_cases) |c| try expect(mem.eql(u8, &c.in, &c.expected));
}
