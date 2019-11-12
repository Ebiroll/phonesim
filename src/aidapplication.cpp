#include "aidapplication.h"
#include "simfilesystem.h"
#include "simauth.h"

#include <qatutils.h>
#include <qsimcontrolevent.h>

AidApplication::AidApplication( QObject *parent, SimXmlNode& n )
    : QObject( parent )
{
    SimXmlNode *child = n.children;

    type = n.getAttribute( "type" );
    aid = n.getAttribute( "id" );

    while (child) {
        if ( child->tag == "filesystem" )
            fs = new SimFileSystem( (SimRules *)parent, *child, FILE_SYSTEM_TYPE_ISIM );

        child = child->next;
    }
}

AidApplication::~AidApplication()
{
}

AidAppWrapper::AidAppWrapper( SimRules *r, QList<AidApplication *> apps, SimAuth *sa ) : QObject( r )
{
    applications = apps;
    session_start = 257;
    rules = r;
    auth = sa;
}

AidAppWrapper::~AidAppWrapper()
{
}

bool AidAppWrapper::command( const QString& cmd )
{
    if ( cmd.startsWith( "AT+CUAD") ) {
        QString response( "+CUAD: " );

        if ( cmd.contains("=?") ) {
            rules->respond( "OK" );
            return true;
        }

        for ( AidApplication* app : qAsConst(applications) )
        response += app->getAid();

        response.append( "\n\nOK" );

        rules->respond( response );

        return true;
    } else if ( cmd.startsWith( "AT+CCHO" ) ) {
        QString aid;
        int session_id = -1;

        if ( !cmd.contains("=") ) {
            rules->respond( "ERROR" );
            return true;
        }

        if ( cmd.contains("=?") ) {
            rules->respond( "OK" );
            return true;
        }

        aid = cmd.split('=')[1];
        aid = aid.replace("\"", "");

        for ( AidApplication* app : qAsConst(applications) ) {
            if ( app->getAid().contains( aid ) ) {
                if ( sessions.size() >= MAX_LOGICAL_CHANNELS )
                    break;

                sessions.insert( session_start, app );
                session_id = session_start;
                session_start++;
                break;
            }
        }

        if ( session_id == -1 ) {
            rules->respond( "ERROR" );
            return true;
        }

        rules->respond( QString( "+CCHO: %1\n\nOK" ).arg(session_id, 0, 10) );
        return true;
    } else if ( cmd.startsWith( "AT+CCHC" ) ) {
        int session_id = -1;

        if ( !cmd.contains("=") ) {
            rules->respond( "ERROR" );
            return true;
        }

        if ( cmd.contains("=?") ) {
            rules->respond( "OK" );
            return true;
        }

        session_id = cmd.split('=')[1].toInt();

        sessions.remove( session_id );

        rules->respond( "OK" );
        return true;
    } else if ( cmd.startsWith( "AT+CRLA" ) ) {
        QString resp;
        AidApplication *app;
        QStringList params = cmd.split('=')[1].split(',');

        int session_id = params[0].toInt();

        if ( !sessions.contains( session_id ) ) {
            rules->respond( "ERROR" );
            return true;
        }

        app = sessions[session_id];
        if (!app) {
            rules->respond( "ERROR" );
            return true;
        }

        QString file_cmd;
        QString response = "+CRLA: ";

        for (int i = 1; i < params.length(); i++) {
            file_cmd += params[i];

            if (i != params.length() - 1)
                file_cmd += ",";
        }

        bool ok = app->fs->fileAccess( file_cmd, resp );

        if (!ok) {
            rules->respond( "OK" );
            return true;
        }

        response += resp;

        rules->respond( response );
        rules->respond( "OK" );

        return true;
    } else if ( cmd.startsWith( "AT+CGLA" ) ) {
        QString auth_data;
        QString command;
        QString resp;
        AidApplication *app;
        QStringList params = cmd.split('=')[1].split(',');

        int session_id = params[0].toInt();

        if ( !sessions.contains( session_id ) ) {
            rules->respond( "ERROR" );
            return true;
        }

        app = sessions[session_id];
        if (!app) {
            rules->respond( "ERROR" );
            return true;
        }

        command = params[2].replace("\"", "");
        auth_data = command.mid(10);

        switch (checkCommand(app, command)) {
        case CMD_TYPE_GSM_AUTH:
        {
            QString sres, kc;
            QString rand = auth_data.mid(2, 32);
            auth->gsmAuthenticate(rand, sres, kc);

            resp = QString( "+CGLA: 32,\"04 %1 08 %2 \"" )
                                        .arg( sres, kc );
            resp.replace( " ", "");

            rules->respond( resp );
            rules->respond( "OK" );

            return true;
        }
        break;
        case CMD_TYPE_UMTS_AUTH:
        {
            enum UmtsStatus status;
            QString res, ck, ik, auts;
            QString rand = auth_data.mid(2, 32);
            QString autn = auth_data.mid(36, 32);

            status = auth->umtsAuthenticate( rand, autn, res, ck, ik, auts );
            resp = QString("+CGLA: ");

            QString test;

            switch (status) {
            case UMTS_OK:
                resp += QString( "88,\"DB08 %1 10 %2 10 %3\"" )
                .arg( res, ck, ik );
                resp.replace( " ", "" );

                break;
            case UMTS_INVALID_MAC:
                resp += QString( "4,\"%1\"")
                .arg( CMD_TYPE_APP_ERROR, 0, 16 );

                break;
            case UMTS_SYNC_FAILURE:
                resp += QString( "34,\"DC0E %1 \"" ).arg( auts );
                resp.replace( " ", "" );

                break;
            case UMTS_ERROR:
                rules->respond( "ERROR" );
                return true;
            }

            rules->respond( resp );
            rules->respond( "OK" );
        }
        break;
        default:
            return false;
        }
    }

    return false;
}

enum CmdType AidAppWrapper::checkCommand( AidApplication *app, QString command)
{
    QString cls = command.mid(0, 2);
    QString ins = command.mid(2, 2);
    QString p1 = command.mid(4, 2);
    QString p2 = command.mid(6, 2);
    QString lc = command.mid(8, 2);

    if ( cls != "00" )
        return CMD_TYPE_UNSUPPORTED_CLS;

    if ( ins != "88" )
        return CMD_TYPE_UNSUPPORTED_INS;

    if ( p1 != "00" )
        return CMD_TYPE_INCORRECT_P2_P1;

    if ( p2 == "80" ) {
        if ( lc != "11" )
            return CMD_TYPE_WRONG_LENGTH;

        if ( !(app->getType() == "USim" || app->getType() == "ISim") )
            return CMD_TYPE_APP_ERROR;

        return CMD_TYPE_GSM_AUTH;
    } else if ( p2 == "81" ) {
        if ( lc != "22" )
            return CMD_TYPE_WRONG_LENGTH;

        if ( app->getType() != "ISim" )
            return CMD_TYPE_APP_ERROR;

        return CMD_TYPE_UMTS_AUTH;
    } else {
        return CMD_TYPE_UNKNOWN;
    }
}
