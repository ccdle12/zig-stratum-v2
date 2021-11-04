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

pub const hash_len = 32;
pub const key_len = 32;
pub const block_len = 64;
pub const mac_len = 16;
pub const max_msg_len = 65535;

pub const empty_key = [_]u8{0} ** 32;
pub const empty_hash = [_]u8{0} ** 32;

const Error = error{
    EndOfBuffer,
};

pub const NoiseSession = struct {
    hs: HandshakeState,
    h: [hash_len]u8,
    cs1: CipherState,
    cs2: CipherState,
    mc: u128,
    i: bool,
    is_transport: bool,

    pub fn init_initiator(prologue: []const u8, s: Ed25519.KeyPair) NoiseSession {
        return .{
            .hs = HandshakeState.init(true, prologue, s, empty_key),
            .h = empty_hash,
            .cs1 = CipherState.init(),
            .cs2 = CipherState.init(),
            .mc = 0,
            .i = true,
            .is_transport = false,
        };
    }

    pub fn init_responder(prologue: []const u8, s: Ed25519.KeyPair) NoiseSession {
        return .{
            .hs = HandshakeState.init(false, prologue, s, empty_key),
            .h = empty_hash,
            .cs1 = CipherState.init(),
            .cs2 = CipherState.init(),
            .mc = 0,
            .i = false,
            .is_transport = false,
        };
    }

    pub fn send_msg(self: *NoiseSession, msg: []u8) !void {
        if (msg.len < mac_len or msg.len > max_msg_len)
            return error.EndOfBuffer;

        if (self.mc == 0) {
            try self.hs.write_msg_a(msg);
        } else if (self.mc == 1) {
            const tmp = try self.hs.write_msg_b(msg);
            self.h = tmp.hash;
            self.is_transport = true;
            self.cs1 = tmp.cs1;
            self.cs2 = tmp.cs2;
            self.hs.clear();
        } else if (self.i) {
            self.cs1.write_msg_regular(msg);
        } else {
            self.cs2.write_msg_regular(msg);
        }

        self.mc += 1;
    }

    pub fn read_msg(self: *NoiseSession, msg: []u8) !void {
        if (msg.len < mac_len or msg.len > max_msg_len)
            return error.EndOfBuffer;

        if (self.mc == 0) {
            try self.hs.read_msg_a(msg);
        } else if (self.mc == 1) {
            const tmp = try self.hs.read_msg_b(msg);
            self.h = tmp.hash;
            self.is_transport = true;
            self.cs1 = tmp.cs1;
            self.cs2 = tmp.cs2;
            self.hs.clear();
        } else if (self.i) {
            try self.cs2.read_msg_regular(msg);
        } else {
            try self.cs1.read_msg_regular(msg);
        }

        self.mc += 1;
    }
};

pub const HandshakeState = struct {
    ss: SymmetricState,

    /// The local static keypair
    s: ?Ed25519.KeyPair,

    /// The local ephemeral key pair
    e: ?Ed25519.KeyPair,

    /// The remote parties static public key
    rs: [key_len]u8,

    /// The remote parties ephemeral public key
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

    pub fn write_msg_a(self: *HandshakeState, msg: []u8) !void {
        if (msg.len < key_len) return error.EndOfBuffer;
        if (self.e == null) self.e = try Ed25519.KeyPair.create(null);

        var ne = msg[0..key_len];
        mem.copy(u8, ne, &self.e.?.public_key);
        self.ss.mix_hash(ne);

        self.ss.mix_hash(msg[key_len..]);
    }

    pub const CipherStateResult = struct {
        hash: [hash_len]u8,
        cs1: CipherState,
        cs2: CipherState,
    };

    pub fn write_msg_b(self: *HandshakeState, msg: []u8) !CipherStateResult {
        if (msg.len < key_len) return error.EndOfBuffer;
        if (self.e == null) self.e = try Ed25519.KeyPair.create(null);

        var ne = msg[0..key_len];
        var in_out = msg[key_len..];
        mem.copy(u8, ne, &self.e.?.public_key);
        self.ss.mix_hash(ne);

        self.ss.mix_key(&try dh(self.e.?, self.re));

        var ns = in_out[0 .. key_len + mac_len];
        var in_out_2 = in_out[key_len + mac_len ..];
        mem.copy(u8, ns, &self.s.?.public_key);
        try self.ss.encrypt_and_hash(ns);

        self.ss.mix_key(&try dh(self.s.?, self.re));
        try self.ss.encrypt_and_hash(in_out_2);

        const cs = self.ss.split();
        self.ss.clear();

        return CipherStateResult{
            .hash = self.ss.h,
            .cs1 = cs[0],
            .cs2 = cs[1],
        };
    }

    pub fn read_msg_b(self: *HandshakeState, msg: []u8) !CipherStateResult {
        if (msg.len < mac_len + key_len) return error.EndOfBuffer;

        var re = msg[0..key_len];
        var in_out = msg[key_len..];
        mem.copy(u8, &self.re, re);
        self.ss.mix_hash(&self.re);

        self.ss.mix_key(&try dh(self.e.?, self.re));

        var rs = in_out[0 .. key_len + mac_len];
        var in_out_2 = in_out[key_len + mac_len ..];
        try self.ss.decrypt_and_hash(rs);

        mem.copy(u8, &self.rs, rs[0..key_len]);
        self.ss.mix_key(&try dh(self.e.?, self.rs));

        try self.ss.decrypt_and_hash(in_out_2);

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

    pub fn read_msg_a(self: *HandshakeState, msg: []u8) !void {
        if (msg.len < key_len + mac_len) return error.EndOfBuffer;
        mem.copy(u8, &self.re, msg[0..key_len]);
        self.ss.mix_hash(&self.re);
        self.ss.mix_hash(msg[key_len..]);
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

        var tmp_k = empty_key;
        mem.copy(u8, &tmp_k, &out1);

        self.cs = CipherState.from_key(tmp_k);
    }

    pub fn encrypt_and_hash(self: *SymmetricState, msg: []u8) !void {
        var tmp_mac = [_]u8{0} ** mac_len;

        // TODO: Check for under/overflow bug
        var plain_text = msg[0 .. msg.len - mac_len];
        var mac = msg[msg.len - mac_len ..];

        self.cs.encrypt_with_ad(&self.h, plain_text, &tmp_mac);

        mem.copy(u8, mac, &tmp_mac);
        self.mix_hash(msg);
    }

    pub fn decrypt_and_hash(self: *SymmetricState, msg: []u8) !void {
        var tmp: [2048]u8 = undefined;
        mem.copy(u8, tmp[0..msg.len], msg);

        var ciphertext = msg[0 .. msg.len - mac_len];
        var mac = msg[msg.len - mac_len ..];
        var tmp_mac: [mac_len]u8 = undefined;
        mem.copy(u8, &tmp_mac, mac);

        try self.cs.decrypt_with_ad(&self.h, ciphertext, tmp_mac);
        self.mix_hash(tmp[0..msg.len]);
    }

    pub fn split(self: SymmetricState) [2]CipherState {
        var tmp_k1 = empty_hash;
        var tmp_k2 = empty_hash;
        var out2 = empty_hash;

        hkdf(
            &self.ck,
            &[0]u8{},
            2,
            &tmp_k1,
            &tmp_k2,
            &out2,
        );

        var cs1 = CipherState.from_key(tmp_k1);
        var cs2 = CipherState.from_key(tmp_k2);

        return [_]CipherState{ cs1, cs2 };
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
        if (!mem.eql(u8, &self.k, &empty_key)) {
            encrypt(msg, mac, ad, self.n, self.k);
            self.n += 1;
        }
    }

    pub fn decrypt_with_ad(
        self: *CipherState,
        ad: []const u8,
        msg: []u8,
        mac: [mac_len]u8,
    ) !void {
        if (!mem.eql(u8, &self.k, &empty_key)) {
            try decrypt(msg, mac, ad, self.n, self.k);
            self.n += 1;
        }
    }

    pub fn write_msg_regular(self: *CipherState, msg: []u8) void {
        var in_out = msg[0 .. msg.len - mac_len];
        var mac = msg[msg.len - mac_len ..];
        var tmp_mac = [_]u8{0} ** mac_len;

        var zerolen = [0]u8{};
        self.encrypt_with_ad(&zerolen, in_out, &tmp_mac);
        mem.copy(u8, mac, &tmp_mac);
    }

    pub fn read_msg_regular(self: *CipherState, msg: []u8) !void {
        var in_out = msg[0 .. msg.len - mac_len];
        var mac = msg[msg.len - mac_len ..];

        var tmp_mac = [_]u8{0} ** mac_len;
        mem.copy(u8, &tmp_mac, mac);

        var zerolen = [_]u8{};
        try self.decrypt_with_ad(&zerolen, in_out, tmp_mac);
    }
};

fn encrypt(
    output: []u8,
    mac: *[mac_len]u8,
    ad: []const u8,
    nonce: u64,
    k: [key_len]u8,
) void {
    ChaCha20Poly1305.encrypt(output, mac, output, ad, nonce_to_bytes(nonce), k);
}

fn decrypt(
    output: []u8,
    mac: [mac_len]u8,
    ad: []const u8,
    nonce: u64,
    k: [key_len]u8,
) !void {
    try ChaCha20Poly1305.decrypt(output, output, mac, ad, nonce_to_bytes(nonce), k);
}

fn nonce_to_bytes(nonce: u64) [12]u8 {
    const b7: u8 = @intCast(u8, ((nonce >> 56) & 0xff));
    const b6: u8 = @intCast(u8, ((nonce >> 48) & 0xff));
    const b5: u8 = @intCast(u8, ((nonce >> 40) & 0xff));
    const b4: u8 = @intCast(u8, ((nonce >> 32) & 0xff));
    const b3: u8 = @intCast(u8, ((nonce >> 24) & 0xff));
    const b2: u8 = @intCast(u8, ((nonce >> 16) & 0xff));
    const b1: u8 = @intCast(u8, ((nonce >> 8) & 0xff));
    const b0: u8 = @intCast(u8, ((nonce >> 0) & 0xff));

    return [_]u8{ 0, 0, 0, 0, b0, b1, b2, b3, b4, b5, b6, b7 };
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
    var tmp_key = empty_key;
    hmac(chaining_key, input_key_material, &tmp_key);
    hmac(&tmp_key, &[_]u8{1}, out1);
    if (outputs == 1) return;

    var in2 = [_]u8{0} ** (hash_len + 1);
    mem.copy(u8, &in2, out1);

    in2[hash_len] = 2;
    hmac(&tmp_key, &in2, out2);
    if (outputs == 2) return;

    var in3 = [_]u8{0} ** (hash_len + 1);
    mem.copy(u8, &in3, out2);
    in3[hash_len] = 3;
    hmac(&tmp_key, &in3, out3);
}

test "full handshake" {
    var responder = NoiseSession.init_responder("", try Ed25519.KeyPair.create(null));
    var initiator = NoiseSession.init_initiator("", try Ed25519.KeyPair.create(null));

    var buf = [_]u8{0} ** 1024;

    // -> e
    try initiator.send_msg(&buf);
    try responder.read_msg(&buf);

    try expect(initiator.mc == 1 and responder.mc == 1);
    try expect(mem.eql(u8, &initiator.hs.ss.h, &responder.hs.ss.h));

    // <- e..
    try responder.send_msg(&buf);
    try initiator.read_msg(&buf);

    try expect(responder.mc == 2 and initiator.mc == 2);
    try expect(responder.is_transport and initiator.is_transport);
    try expect(mem.eql(u8, &initiator.hs.ss.h, &responder.hs.ss.h));

    var frame = [_]u8{0} ** 1024;
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
