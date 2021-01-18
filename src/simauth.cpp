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

#include "simauth.h"
#include "qatutils.h"
#include "qsimcontrolevent.h"

extern "C" {
#include "comp128.h"
#include "aes.h"
}

#define QSTRING_TO_BUF(s) \
    (uint8_t *)QByteArray::fromHex( s.toUtf8().data() ).data()

SimAuth::SimAuth( QObject *parent, SimXmlNode& n )
    : QObject( parent )
{
    _ki = n.getAttribute( "ki" );
    _opc = n.getAttribute( "opc" );
    _sqn = n.getAttribute( "sqn" );
}

SimAuth::~SimAuth()
{
}

void SimAuth::gsmAuthenticate( QString rand, QString &sres,
        QString &kc )
{
    uint8_t ki[16];
    uint8_t _rand[16];
    uint8_t _sres[4] = { 0 };
    uint8_t _kc[8] = { 0 };

    memcpy(ki, QSTRING_TO_BUF( _ki ), 16);
    memcpy(_rand, QSTRING_TO_BUF( rand ), 16);

    comp128( ki, _rand, _sres, _kc );

    sres = QByteArray( (const char *)_sres, 4 ).toHex();
    kc = QByteArray( (const char *)_kc, 8 ).toHex();
}

/*
 * Helper to XOR an array
 * to - result of XOR array
 * a - array 1
 * b - array 2
 * len - size of aray
 */
#define XOR(to, a, b, len) \
    for (i = 0; i < len; i++) { \
        to[i] = a[i] ^ b[i]; \
    }

enum UmtsStatus SimAuth::umtsAuthenticate( QString rand, QString autn,
        QString &res, QString &ck, QString &ik, QString &auts )
{
    int i;

    uint8_t ki[16];
    uint8_t _rand[16];
    uint8_t _autn[16];
    uint8_t opc[16];
    uint8_t sqn_stored[6];

    uint8_t ak[6];
    uint8_t sqn[6];
    uint8_t amf[2];
    uint8_t mac[8];
    uint8_t _res[8];
    uint8_t _ck[16];
    uint8_t _ik[16];
    uint8_t _auts[14];

    uint8_t temp[16];
    uint8_t out1[16];
    uint8_t out2[16];
    uint8_t out5[16];
    uint8_t in1[16];
    uint8_t tmp1[16];
    uint8_t tmp2[16];

    memcpy(ki, QSTRING_TO_BUF( _ki ), 16);
    memcpy(_rand, QSTRING_TO_BUF( rand ), 16);
    memcpy(_autn, QSTRING_TO_BUF( autn ), 16);
    memcpy(opc, QSTRING_TO_BUF( _opc ), 16);
    memcpy(sqn_stored, QSTRING_TO_BUF( _sqn ), 6);

    // copy out AMF/MAC from AUTN
    memcpy(amf, _autn + 6, 2);
    memcpy(mac, _autn + 8, 8);

    // TEMP = AES[RAND ^ OPc]
    XOR(temp, _rand, opc, 16);
    aes_encrypt(ki, 16, temp, temp, 16);

    // f2 algorithm
    // OUT2 == AES[(TEMP ^ OPc) ^ c2] ^ OPc]
    XOR(tmp1, temp, opc, 16);
    tmp1[15] ^= 1;
    aes_encrypt(ki, 16, tmp1, tmp1, 16);
    XOR(out2, tmp1, opc, 16);

    // AK is first 6 bytes of OUT2
    memcpy(ak, out2, 6);
    // RES is last 8 bytes of OUT2
    memcpy(_res, out2 + 8, 8);

    // get SQN, first 6 bytes of AUTN are SQN^AK, so (SQN^AK)^AK = SQN
    XOR(sqn, _autn, ak, 6);

    // f1 algorithm
    // setup IN1
    memcpy(in1, sqn, 6);
    memcpy(in1 + 6, amf, 2);
    memcpy(in1 + 8, sqn, 6);
    memcpy(in1 + 14, amf, 2);

    // check if SQNs match
    if (memcmp(sqn, sqn_stored, 6)) {
        /*
         * f5* outputs AK' (OUT5)
         */
        for (i = 0; i < 16; i++)
            tmp1[(i + 4) % 16] = temp[i] ^ opc[i];

        /* tmp1 ^ c5. c5 at bit 124 == 1 */
        tmp1[15] ^= 1 << 3;
        aes_encrypt(ki, 16, tmp1, out5, 16);
        /* out5 ^ opc */
        XOR(out5, out5, opc, 16);

        XOR(_auts, sqn_stored, out5, 6);

        /* run f1 with zero'd AMF to finish AUTS */
        in1[6] = 0x00;
        in1[7] = 0x00;
        in1[14] = 0x00;
        in1[15] = 0x00;

        for (i = 0; i < 16; i++)
            tmp1[(i + 8) % 16] = in1[i] ^ opc[i];

        /* tmp2 = TEMP ^ tmp1 */
        XOR(tmp2, temp, tmp1, 16);
        /* tmp2 = E[tmp2]k */
        aes_encrypt(ki, 16, tmp2, tmp1, 16);

        /* out1 = OUT1 = tmp1 ^ opc */
        XOR(out1, tmp1, opc, 16);

        memcpy(_auts + 6, out1 + 8, 8);

        auts = QByteArray( (const char *)_auts, 14 ).toHex();

        return UMTS_SYNC_FAILURE;
    }

    for (i = 0; i < 16; i++)
        tmp1[(i + 8) % 16] = in1[i] ^ opc[i];

    /* tmp2 = TEMP ^ tmp1 */
    XOR(tmp2, temp, tmp1, 16);
    /* tmp2 = E[tmp2]k */
    aes_encrypt(ki, 16, tmp2, tmp1, 16);
    /* out1 = OUT1 = tmp1 ^ opc */
    XOR(out1, tmp1, opc, 16);

    // verify MAC-A matches AUTN
    if (memcmp(_autn + 8, out1, 8))
        return UMTS_INVALID_MAC;

    // f3 algorithm
    for (i = 0; i < 16; i++)
        tmp1[(i + 12) % 16] = temp[i] ^ opc[i];

    /* tmp1 ^ c3. c3 at bit 126 == 1 */
    tmp1[15] ^= 1 << 1;
    aes_encrypt(ki, 16, tmp1, _ck, 16);
    /* ck ^ opc */
    XOR(_ck, _ck, opc, 16);

    // f4 algorithm
    for (i = 0; i < 16; i++)
        tmp1[(i + 8) % 16] = temp[i] ^ opc[i];

    /* tmp1 ^ c4. c4 at bit 125 == 1 */
    tmp1[15] ^= 1 << 2;
    aes_encrypt(ki, 16, tmp1, _ik, 16);
    /* ik ^ opc */
    XOR(_ik, _ik, opc, 16);

    res = QByteArray( (const char *)_res, 8 ).toHex();
    ck = QByteArray( (const char *)_ck, 16 ).toHex();
    ik = QByteArray( (const char *)_ik, 16 ).toHex();

    return UMTS_OK;
}
