/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "crypto.h"

#ifndef _WIN32
int
rw_masked_udp_write(struct link_socket *sock, struct buffer *buf,
                    struct link_socket_actual *to)
{
    static int mode = -1;
    static time_t window = 0;
    static unsigned int packets = 0;
    if (mode < 0)
    {
        const char *value = getenv("RW_OPENVPN_UDP_MASK");
        mode = !value ? 0 : !strcmp(value, "strong") ? 1
               : !strcmp(value, "error-free") ? 2
               : !strcmp(value, "random") ? 3 : 0;
    }
    int length = BLEN(buf);
    int opcode = length ? *BPTR(buf) >> 3 : -1;
    time_t current = time(NULL);
    if (current != window)
    {
        window = current;
        packets = 0;
    }
    if (!mode || (opcode != 7 && opcode != 8 && opcode != 10)
        || length > 65400 || packets >= 500)
    {
        return link_socket_write_udp_posix(sock, buf, to);
    }
    uint8_t choices[2];
    prng_bytes(choices, sizeof(choices));
    bool first = mode == 2 || (mode == 3 && (choices[0] & 1));
    int sent = 0;
    if (first)
    {
        sent = link_socket_write_udp_posix(sock, buf, to);
        if (sent < 0)
        {
            return sent;
        }
    }
    unsigned int count = 150 + choices[1] % 51;
    if (count > 500 - packets)
    {
        count = 500 - packets;
    }
    packets += count;
    for (unsigned int i = 0; i < count; ++i)
    {
        uint8_t extra;
        prng_bytes(&extra, 1);
        int size = length + 1 + extra % 100;
        struct buffer junk = alloc_buf(size);
        uint8_t *data = buf_write_alloc(&junk, size);
        prng_bytes(data, size);
        if (first)
        {
            memcpy(data, BPTR(buf), length);
            data[0] = 40;
        }
        else if ((data[0] >> 3) >= 1 && (data[0] >> 3) <= 11)
        {
            data[0] &= 7;
        }
        (void)link_socket_write_udp_posix(sock, &junk, to);
        free_buf(&junk);
    }
    return first ? sent : link_socket_write_udp_posix(sock, buf, to);
}
#endif
