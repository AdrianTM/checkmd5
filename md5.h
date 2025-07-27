#pragma once

#include <QByteArray>
#include <cstdint>

class MD5
{
public:
    MD5();
    void update(const QByteArray& data);
    void update(const uint8_t* data, size_t length);
    QByteArray finalize();

    static QByteArray hash(const QByteArray& data);

private:
    struct Context {
        uint32_t buf[4];
        uint32_t bytes[2];
        uint8_t in[64];
    };

    Context m_context;
    bool m_finalized = false;

    static void byteReverse(uint8_t* buf, unsigned longs);
    static void transform(uint32_t buf[4], const uint32_t in[16]);
};
