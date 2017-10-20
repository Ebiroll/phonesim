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

#ifndef SIMAUTH_H
#define SIMAUTH_H

#include "phonesim.h"

#define MAX_LOGICAL_CHANNELS    4

enum AidType {
    AID_TYPE_USIM,
    AID_TYPE_ISIM,
    AID_TYPE_UNKNOWN
};

/*
 * Some common errors
 */
enum CmdType {
    CMD_TYPE_GSM_AUTH = 0,
    CMD_TYPE_UMTS_AUTH = 1,
    CMD_TYPE_UNSUPPORTED_CLS = 0x6E00,
    CMD_TYPE_UNSUPPORTED_INS = 0x6D00,
    CMD_TYPE_INCORRECT_P2_P1 = 0x6A86,
    CMD_TYPE_WRONG_LENGTH = 0x6700,
    CMD_TYPE_APP_ERROR = 0x9862,
    CMD_TYPE_UNKNOWN = 0xFFFF
};

enum UmtsStatus {
    UMTS_OK,            // Success
    UMTS_INVALID_MAC,   // MAC did not match AUTN parameter
    UMTS_SYNC_FAILURE,  // SQN did not match
    UMTS_ERROR          // Any other error
};

class SimAuth : public QObject
{
    Q_OBJECT
public:
    SimAuth( QObject *parent, SimXmlNode& n );
    ~SimAuth();

    // Process an AT command.  Returns false if not a call-related command.
    bool command( const QString& cmd );

signals:
    // Send a response to a command.
    void send( const QString& line );

private:
    // secret key, set during initialization (from XML)
    QString _ki;

    // operator variant algorithm configuration field
    QString _opc;

    // Sequence number stored on SIM
    QString _sqn;

    // arbitrary session ID starting number
    int _session_start;

    // parsed list of AID's
    QStringList _aid_list;

    // map of logical channel integers to AID's
    QMap<int, QString> _logical_channels;

    // run COMP128v1 algorithm against 'rand' and 'ki'
    void gsmAuthenticate( QString rand, QString &sres, QString &kc );

    // run Milenage algorithm with ki, rand, and autn
    enum UmtsStatus umtsAuthenticate( QString rand, QString autn,
            QString &res, QString &ck, QString &ik, QString &auts);

    // open an AID logical channel
    int openChannel( QString aid );

    // close an AID logical channel
    void closeChannel( int session_id );

    // find the AID from a given session ID
    bool getAidFromSession( int session_id, QString& aid );

    // checks that the AID supports the given command
    enum CmdType checkCommand( QString command, QString aid );

    // returns the type of AID (USIM/ISIM/UNKNOWN)
    enum AidType getAidType( QString aid );
};

#endif
