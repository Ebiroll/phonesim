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

#ifndef COMP128_H
#define COMP128_H

#ifdef __cplusplus
extern "C" {
#endif

void comp128(const uint8_t *ki, const uint8_t *rand, uint8_t *sres,
        uint8_t *kc);

#ifdef __cplusplus
}
#endif

#endif /* COMP128_H */
