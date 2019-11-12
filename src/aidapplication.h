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

#ifndef AIDAPPLICATION_H
#define AIDAPPLICATION_H

#include "phonesim.h"

#define MAX_LOGICAL_CHANNELS    4

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

/*
 * Class for representing a single AID
 */
class AidApplication : public QObject
{
    Q_OBJECT
public:
    AidApplication( QObject *parent, SimXmlNode& n );
    ~AidApplication() override;

    QString getAid() { return aid; };
    QString getType() { return type; };
    SimFileSystem *fs;

signals:
    // Send a response to a command.
    void send( const QString& line );

private:
    QString aid;
    QString type;
};

/*
 * Wrapper for containing all AIDs on the SIM
 */
class AidAppWrapper : public QObject
{
    Q_OBJECT
public:
    AidAppWrapper( SimRules *r, QList<AidApplication *> apps, SimAuth *auth = nullptr );
    ~AidAppWrapper() override;

    bool command( const QString& cmd );

//signals:
        // Send a response to a command.
//        void send( const QString& line );
private:
    QList<AidApplication *> applications;
    QMap<int, AidApplication*> sessions;
    int session_start;
    SimRules *rules;
    SimAuth *auth;

    enum CmdType checkCommand( AidApplication *app, QString command);

};

#endif
