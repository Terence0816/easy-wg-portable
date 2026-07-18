#pragma once

#include <cstdint>
#include <cstring>

// Compact X25519 public-key derivation fallback for Windows 7.
// Field arithmetic follows the public-domain TweetNaCl approach. This is used
// only when Windows CNG cannot provide the named curve25519 implementation.
namespace easywg_x25519 {

using i64 = std::int64_t;
using u8 = std::uint8_t;
using gf = i64[16];

inline void car25519(gf o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (static_cast<i64>(1) << 16);
        const i64 c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

inline void sel25519(gf p, gf q, int b) {
    const i64 c = ~(static_cast<i64>(b) - 1);
    for (int i = 0; i < 16; ++i) {
        const i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

inline void pack25519(u8 out[32], const gf n) {
    gf m{}, t{};
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);

    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const int b = static_cast<int>((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }

    for (int i = 0; i < 16; ++i) {
        out[2 * i] = static_cast<u8>(t[i] & 0xff);
        out[2 * i + 1] = static_cast<u8>((t[i] >> 8) & 0xff);
    }
}

inline void unpack25519(gf o, const u8 in[32]) {
    for (int i = 0; i < 16; ++i)
        o[i] = static_cast<i64>(in[2 * i]) + (static_cast<i64>(in[2 * i + 1]) << 8);
    o[15] &= 0x7fff;
}

inline void add(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

inline void sub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

inline void mul(gf o, const gf a, const gf b) {
    i64 t[31]{};
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j)
            t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o);
    car25519(o);
}

inline void square(gf o, const gf a) { mul(o, a, a); }

inline void inv25519(gf o, const gf in) {
    gf c{};
    for (int i = 0; i < 16; ++i) c[i] = in[i];
    for (int a = 253; a >= 0; --a) {
        square(c, c);
        if (a != 2 && a != 4) mul(c, c, in);
    }
    for (int i = 0; i < 16; ++i) o[i] = c[i];
}

inline bool scalar_mult(u8 out[32], const u8 scalar[32], const u8 point[32]) {
    static const gf k121665 = {0xDB41, 1};
    u8 z[32]{};
    gf x{}, a{}, b{}, c{}, d{}, e{}, f{};

    std::memcpy(z, scalar, 32);
    z[31] = static_cast<u8>((z[31] & 127) | 64);
    z[0] &= 248;

    unpack25519(x, point);
    for (int i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (int i = 254; i >= 0; --i) {
        const int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        add(e, a, c);
        sub(a, a, c);
        add(c, b, d);
        sub(b, b, d);
        square(d, e);
        square(f, a);
        mul(a, c, a);
        mul(c, b, e);
        add(e, a, c);
        sub(a, a, c);
        square(b, a);
        sub(c, d, f);
        mul(a, c, k121665);
        add(a, a, d);
        mul(c, c, a);
        mul(a, d, f);
        mul(d, b, x);
        square(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }

    inv25519(c, c);
    mul(a, a, c);
    pack25519(out, a);
    return true;
}

inline bool public_from_private(u8 public_key[32], const u8 private_key[32]) {
    u8 basepoint[32]{};
    basepoint[0] = 9;
    return scalar_mult(public_key, private_key, basepoint);
}

} // namespace easywg_x25519
