/****************************************************************************
**
** This file is part of the Qt Extended Opensource Package.
**
** Copyright (C) 2017  Intel Corporation. All rights reserved.
**
** This file may be used under the terms of the GNU General Public License
** version 2.0 as published by the Free Software Foundation and appearing
** in the file LICENSE.GPL included in the packaging of this file.
**
** Please review the following information to ensure GNU General Public
** Licensing requirements will be met:
**     http://www.fsf.org/licensing/licenses/info/GPLv2.html.
**
**
****************************************************************************/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <alloca.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"

#ifndef AF_ALG
#define AF_ALG	38
#define PF_ALG	AF_ALG
#endif

#ifndef HAVE_LINUX_IF_ALG_H
struct sockaddr_alg {
    uint16_t    salg_family;
    uint8_t     salg_type[14];
    uint32_t    salg_feat;
    uint32_t    salg_mask;
    uint8_t     salg_name[64];
};

#define ALG_SET_KEY     1
#define ALG_SET_OP      3
#define ALG_OP_ENCRYPT  1
#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

bool aes_encrypt(const uint8_t *key, size_t key_len, const uint8_t *in,
        uint8_t *out, size_t len)
{
    uint32_t op = ALG_OP_ENCRYPT;
    char *msg_buf;
    size_t msg_size;
    struct msghdr msg;
    struct cmsghdr *c_msg;
    ssize_t result;

    struct sockaddr_alg sa = {
            .salg_family = AF_ALG,
            .salg_type = "skcipher",
            .salg_name = "ecb(aes)"
    };

    struct iovec iov = {
            .iov_base = (void *) in,
            .iov_len = len
    };

    int sock = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa))) {
        close(sock);
        return 0;
    }
    if (setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, key_len)) {
        close(sock);
        return 0;
    }

    int cipher = accept4(sock, NULL, 0, SOCK_CLOEXEC);
    if (cipher == -1) {
        close(sock);
        return 0;
    }
    close(sock);

    msg_size = CMSG_SPACE(sizeof(op));

    msg_buf = alloca(msg_size);

    memset(msg_buf, 0, msg_size);
    memset(&msg, 0, sizeof(msg));

    msg.msg_iov = &iov;
    msg.msg_control = msg_buf;
    msg.msg_controllen = msg_size;
    msg.msg_iovlen = 1;

    c_msg = CMSG_FIRSTHDR(&msg);
    c_msg->cmsg_level = SOL_ALG;
    c_msg->cmsg_type = ALG_SET_OP;
    c_msg->cmsg_len = CMSG_LEN(sizeof(op));
    memcpy(CMSG_DATA(c_msg), &op, sizeof(op));

    result = sendmsg(cipher, &msg, 0);
    if (result < 0) {
        return 0;
    }

    result = read(cipher, out, len);
    if (result < 0) {
        return 0;
    }

    return 1;
}
