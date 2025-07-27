#include "md5.h"
#include <QtEndian>
#include <cstring>

MD5::MD5()
{
    m_context.buf[0] = 0x67452301;
    m_context.buf[1] = 0xefcdab89;
    m_context.buf[2] = 0x98badcfe;
    m_context.buf[3] = 0x10325476;

    m_context.bytes[0] = 0;
    m_context.bytes[1] = 0;
}

void MD5::update(const QByteArray& data)
{
    update(reinterpret_cast<const uint8_t*>(data.constData()), data.size());
}

void MD5::update(const uint8_t* buf, size_t len)
{
    if (m_finalized) {
        return;
    }

    size_t t = m_context.bytes[0] & 0x3F;
    m_context.bytes[0] += len;
    if (m_context.bytes[0] < len) {
        ++(m_context.bytes[1]);
    }

    if (t) {
        uint8_t* p = m_context.in + t;
        t = 64 - t;
        if (len < t) {
            std::memcpy(p, buf, len);
            return;
        }
        std::memcpy(p, buf, t);
        byteReverse(m_context.in, 16);
        transform(m_context.buf, static_cast<uint32_t*>(static_cast<void*>(m_context.in)));
        buf += t;
        len -= t;
    }

    while (len >= 64) {
        std::memcpy(m_context.in, buf, 64);
        byteReverse(m_context.in, 16);
        transform(m_context.buf, static_cast<uint32_t*>(static_cast<void*>(m_context.in)));
        buf += 64;
        len -= 64;
    }

    std::memcpy(m_context.in, buf, len);
}

QByteArray MD5::finalize()
{
    if (m_finalized) {
        return {};
    }

    size_t count = m_context.bytes[0] & 0x3F;
    uint8_t* ptr = m_context.in + count;
    *ptr++ = 0x80;

    count = 64 - 1 - count;

    if (count < 8) {
        std::memset(ptr, 0, count);
        byteReverse(m_context.in, 16);
        transform(m_context.buf, static_cast<uint32_t*>(static_cast<void*>(m_context.in)));
        std::memset(m_context.in, 0, 56);
    } else {
        std::memset(ptr, 0, count - 8);
    }
    byteReverse(m_context.in, 14);

    static_cast<uint32_t*>(static_cast<void*>(m_context.in))[14] = (m_context.bytes[0] << 3);
    static_cast<uint32_t*>(static_cast<void*>(m_context.in))[15]
        = (m_context.bytes[1] << 3) | (m_context.bytes[0] >> 29);

    transform(m_context.buf, static_cast<uint32_t*>(static_cast<void*>(m_context.in)));
    byteReverse(static_cast<uint8_t*>(static_cast<void*>(m_context.buf)), 4);

    QByteArray digest(static_cast<const char*>(static_cast<void*>(m_context.buf)), 16);
    std::memset(&m_context, 0, sizeof(m_context));
    m_finalized = true;

    return digest;
}

QByteArray MD5::hash(const QByteArray& data)
{
    MD5 hasher;
    hasher.update(data);
    return hasher.finalize();
}

void MD5::byteReverse(uint8_t* buf, unsigned longs)
{
    if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
        return;
    }

    while (longs > 0) {
        const uint32_t temp = static_cast<uint32_t>((static_cast<unsigned>(buf[3]) << 8 | buf[2]) << 16
                                                    | (static_cast<unsigned>(buf[1]) << 8 | buf[0]));
        *static_cast<uint32_t*>(static_cast<void*>(buf)) = temp;
        buf += 4;
        --longs;
    }
}

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s) (w += f(x, y, z) + data, w = w << s | w >> (32 - s), w += x)

void MD5::transform(uint32_t buf[4], const uint32_t in[16])
{
    uint32_t a = buf[0];
    uint32_t b = buf[1];
    uint32_t c = buf[2];
    uint32_t d = buf[3];

    // Round 1
    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    // Round 2
    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    // Round 3
    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    // Round 4
    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}
