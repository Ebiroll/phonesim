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

#ifndef CIPHER_H
#define CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

bool aes_encrypt(const uint8_t *key, size_t key_len, const uint8_t *in,
        uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CIPHER_H */
