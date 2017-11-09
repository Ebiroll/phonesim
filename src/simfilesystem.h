/****************************************************************************
**
** This file is part of the Qt Extended Opensource Package.
**
** Copyright (C) 2009 Trolltech ASA.
**
** Contact: Qt Extended Information (info@qtextended.org)
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

#ifndef SIMFILESYSTEM_H
#define SIMFILESYSTEM_H

#include "phonesim.h"

class SimFileItem;

enum file_system_type {
    FILE_SYSTEM_TYPE_DEFAULT,
    FILE_SYSTEM_TYPE_ISIM
};

enum file_type {
    FILE_TYPE_TRANSPARENT = 0,
    FILE_TYPE_LINEAR_FIXED = 1,
    FILE_TYPE_CYCLIC = 3,
    FILE_TYPE_INVALID = 0xff
};

enum file_access {
    FILE_ACCESS_ALWAYS = 0,
    FILE_ACCESS_CHV1 = 1,
    FILE_ACCESS_CHV2 = 2,
    FILE_ACCESS_RESERVED = 3,
    FILE_ACCESS_ADM = 4,
    FILE_ACCESS_NEVER = 15,
};

enum file_op {
    FILE_OP_READ = 20,
    FILE_OP_UPDATE = 16,
    FILE_OP_INCREASE = 12,
    FILE_OP_REHABILITATE = 4,
    FILE_OP_INVALIDATE = 0,
};

class SimFileSystem : public QObject
{
    Q_OBJECT
public:
    SimFileSystem( SimRules *rules, SimXmlNode& e, enum file_system_type type = FILE_SYSTEM_TYPE_DEFAULT );
    ~SimFileSystem();

    // Execute an AT+CRSM command against the filesystem.
    void crsm( const QString& args );

    bool fileAccess( const QString& args, QString& resp );

    // Find an item with a specific id.
    SimFileItem *findItem( const QString& fileid ) const;

    // Find access conditions for an item with a specific id.
    int findItemAccess( const QString& _fileid ) const;

    // Find file type for an item with a specific id.
    enum file_type findItemFileType( const QString& _fileid ) const;

    // Find the parent of an item with a specific id even if the
    // item itself does not exist.  The parameter should be fully qualified.
    SimFileItem *findItemParent( const QString& fileid ) const;

    // Find an item relative to the current item and update current item.
    SimFileItem *findItemRelative( const QString& fileid );

    // Resolve a file identifier to its full path from the root directory.
    QString resolveFileId( const QString& fileid ) const;

    QString resolveISimFileId( const QString& _fileid ) const;

private:
    SimRules *rules;
    SimFileItem *rootItem;
    SimFileItem *currentItem;
};

class SimFileItem : public QObject
{
    Q_OBJECT
public:
    SimFileItem( const QString& fileid, SimFileItem *parentDir,
                 int access = 0, enum file_type type = FILE_TYPE_INVALID);
    ~SimFileItem();

    QString fileid() const { return _fileid; }
    SimFileItem *parentDir() const { return _parentDir; }

    QByteArray contents() const { return _contents; }
    void setContents( const QByteArray& value ) { _contents = value; }

    int recordSize() const { return _recordSize; }
    void setRecordSize( int value ) { _recordSize = value; }

    int access() const { return _access; }
    enum file_type type() const { return _type; }

    bool isDirectory() const { return _isDirectory; }
    void setIsDirectory( bool value ) { _isDirectory = value; }

    QList<SimFileItem *> children() const { return _children; }

    SimFileItem *findItem( const QString& fileid );

    bool checkAccess( enum file_op op, bool havepin ) const;

private:
    QString _fileid;
    SimFileItem *_parentDir;
    QByteArray _contents;
    int _recordSize;
    bool _isDirectory;
    QList<SimFileItem *> _children;
    int _access;
    enum file_type _type;
};

#endif
