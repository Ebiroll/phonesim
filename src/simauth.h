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
    ~SimAuth() override;

    void gsmAuthenticate( QString rand, QString &sres, QString &kc );
    enum UmtsStatus umtsAuthenticate( QString rand, QString autn,
            QString &res, QString &ck, QString &ik, QString &auts );

private:
    // secret key, set during initialization (from XML)
    QString _ki;

    // operator variant algorithm configuration field
    QString _opc;

    // Sequence number stored on SIM
    QString _sqn;
};

#endif
