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
#include <qatutils.h>
#include <qsimcontrolevent.h>

extern "C" {
#include "comp128.h"
#include "aes.h"
}

#define QSTRING_TO_BUF(s) \
    (uint8_t *)QByteArray::fromHex( s.toUtf8().data() ).data()

SimAuth::SimAuth( QObject *parent, SimXmlNode& n )
    : QObject( parent )
{
    SimXmlNode *child = n.children;

    _ki = n.getAttribute( "ki" );
    _opc = n.getAttribute( "opc" );
    _session_start = 257;

    _aid_list = QStringList();

    // parse list of <aid> </aid>
    while (child) {
        if ( child->tag == "aid" )
            _aid_list += QStringList( child->contents );

        child = child->next;
    }
}

SimAuth::~SimAuth()
{
}

bool SimAuth::command( const QString& cmd )
{
    if ( cmd.startsWith( "AT+CUAD") ) {
        QString response( "+CUAD: " );

        if ( cmd.contains("=?") ) {
            emit send( "OK" );
            return true;
        }

        foreach ( const QString &str, _aid_list )
            response += str;

        response.append( "\n\nOK" );

        emit send( response );
    } else if ( cmd.startsWith( "AT+CCHO" ) ) {
        QString aid;
        int session_id = -1;

        if ( !cmd.contains("=") ) {
            emit send( "ERROR" );
            return true;
        }

        if ( cmd.contains("=?") ) {
            emit send( "OK" );
            return true;
        }

        aid = cmd.split('=')[1];
        aid = aid.replace("\"", "");

        foreach ( const QString &str, _aid_list ) {
            if ( str.contains( aid ) ) {
                session_id = openChannel( aid );
                break;
            }
        }

        if ( session_id == -1 ) {
            emit send( "ERROR" );
            return true;
        }

        emit send( QString( "+CCHO: %1\n\nOK" ).arg(session_id, 0, 10) );
    } else if ( cmd.startsWith( "AT+CGLA" ) ) {
        QString aid;
        QString data;
        QString command;
        QString parameters;
        QString response;
        enum CmdType type;
        int session_id = -1;

        if ( !cmd.contains("=") ) {
            emit send( "ERROR" );
            return true;
        }

        if ( cmd.contains("=?") ) {
            emit send( "OK" );
            return true;
        }

        data = cmd.split('=')[1];
        session_id = data.split(',')[0].toInt();

        if (!getAidFromSession( session_id, aid )) {
            emit send( "ERROR" );
            return true;
        }

        data = data.split(',')[2].replace("\"", "");
        parameters = data.mid(10);

        type = checkCommand( data, aid );

        if (type == CMD_TYPE_GSM_AUTH) {
            QString sres, kc;
            QString rand = parameters.mid(2, 32);

            gsmAuthenticate( rand, sres, kc );

            response = QString( "+CGLA: 32,\"04 %1 08 %2 \"\n\nOK" )
                    .arg( sres, kc );
            response.replace( " ", "");

        } else if (type == CMD_TYPE_UMTS_AUTH) {
            enum UmtsStatus status;
            QString res, ck, ik, auts;
            QString rand = parameters.mid(2, 32);
            QString autn = parameters.mid(36, 32);

            status = umtsAuthenticate( rand, autn, res, ck, ik, auts );

            response = QString("+CGLA: ");

            QString test;

            switch (status) {
            case UMTS_OK:
                response += QString( "88,\"DB08 %1 10 %2 10 %3\"\n\nOK" )
                        .arg( res, ck, ik );
                response.replace( " ", "" );

                break;
            case UMTS_INVALID_MAC:
                response += QString( "4,\"%1\"\n\nOK")
                        .arg( CMD_TYPE_APP_ERROR, 0, 16 );

                break;
            case UMTS_SYNC_FAILURE:
                response == QString( "34,\"DC10 %1 \"\n\nOK" ).arg( auts );
                response.replace( " ", "" );

                break;
            case UMTS_ERROR:
                response = QString( "ERROR" );

                break;
            }
        } else {
            response = QString("+CGLA: 4,\"%1\"\n\nOK").arg(type, 0, 16);
        }

        emit send( response );
    } else if ( cmd.startsWith( "AT+CCHC" ) ) {
        int session_id = -1;

        if ( !cmd.contains("=") ) {
            emit send( "ERROR" );
            return true;
        }

        if ( cmd.contains("=?") ) {
            emit send( "OK" );
            return true;
        }

        session_id = cmd.split('=')[1].toInt();

        closeChannel(session_id);

        emit send( "OK" );
    } else {
        return false;
    }

    return true;
}

int SimAuth::openChannel( QString aid )
{
    if ( _logical_channels.size() >= MAX_LOGICAL_CHANNELS )
        return -1;

    _logical_channels.insert( _session_start, aid );

    return _session_start++;
}

void SimAuth::closeChannel( int session_id )
{
    _logical_channels.remove( session_id );
}

bool SimAuth::getAidFromSession( int session_id, QString& aid )
{
    if ( _logical_channels.contains( session_id ) ) {
        aid = _logical_channels[session_id];
        return true;
    }

    return false;
}

enum AidType SimAuth::getAidType( QString aid )
{
    if ( aid.mid(10, 4) == "1004" )
        return AID_TYPE_ISIM;
    else if ( aid.mid(10, 4) == "1002")
        return AID_TYPE_USIM;

    return AID_TYPE_UNKNOWN;
}


enum CmdType SimAuth::checkCommand( QString command, QString aid )
{
    QString cls = command.mid(0, 2);
    QString ins = command.mid(2, 2);
    QString p1 = command.mid(4, 2);
    QString p2 = command.mid(6, 2);
    QString lc = command.mid(8, 2);
    AidType type = getAidType( aid );

    if ( cls != "00" )
        return CMD_TYPE_UNSUPPORTED_CLS;

    if ( ins != "88" )
        return CMD_TYPE_UNSUPPORTED_INS;

    if ( p1 != "00" )
        return CMD_TYPE_INCORRECT_P2_P1;

    if ( p2 == "80" ) {
        if ( lc != "11" )
            return CMD_TYPE_WRONG_LENGTH;

        if ( !(type == AID_TYPE_USIM || type == AID_TYPE_ISIM) )
            return CMD_TYPE_APP_ERROR;

        return CMD_TYPE_GSM_AUTH;
    } else if ( p2 == "81" ) {
        if ( lc != "22" )
            return CMD_TYPE_WRONG_LENGTH;

        if ( type != AID_TYPE_ISIM )
            return CMD_TYPE_APP_ERROR;

        return CMD_TYPE_UMTS_AUTH;
    } else {
        return CMD_TYPE_UNKNOWN;
    }
}

void SimAuth::gsmAuthenticate( QString rand, QString &sres,
        QString &kc )
{
    uint8_t *ki = QSTRING_TO_BUF( _ki );
    uint8_t *_rand = QSTRING_TO_BUF( rand );
    uint8_t _sres[4];
    uint8_t _kc[8];

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

    uint8_t *ki = QSTRING_TO_BUF( _ki );
    uint8_t *_rand = QSTRING_TO_BUF( rand );
    uint8_t *_autn = QSTRING_TO_BUF( autn );
    uint8_t *opc = QSTRING_TO_BUF( _opc );

    uint8_t ak[6];
    uint8_t sqn[6];
    uint8_t amf[2];
    uint8_t mac[8];
    uint8_t _res[8];
    uint8_t _ck[16];
    uint8_t _ik[16];

    uint8_t temp[16];
    uint8_t out1[16];
    uint8_t out2[16];
    uint8_t in1[16];
    uint8_t tmp1[16];
    uint8_t tmp2[16];

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

    for (i = 0; i < 16; i++)
        tmp1[(i + 8) % 16] = in1[i] ^ opc[i];

    /* tmp2 = TEMP ^ tmp1 */
    XOR(tmp2, temp, tmp1, 16);
    /* tmp2 = E[tmp2]k */
    aes_encrypt(ki, 16, tmp2, tmp1, 16);
    /* out1 = OUT1 = tmp1 ^ opc */
    XOR(out1, tmp1, opc, 16);

    if (memcmp(_autn + 8, out1, 8)) {
        // f5* algorithm
        // rot(TEMP ^ OPC, r5)
        for (i = 0; i < 16; i++)
            tmp1[(i + 4) % 16] = temp[i] ^ opc[i];

        // XOR with c5
        tmp1[15] ^= 1 << 3;
        aes_encrypt(ki, 16, tmp1, tmp1, 16);
        // XOR with OPc
        XOR(tmp1, opc, tmp1, 16);

        auts = QByteArray( (const char *)tmp1, 16 ).toHex();

        return UMTS_INVALID_MAC;
    }

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
