AC_PREREQ(2.60)
AC_INIT(phonesim, 1.21)

AM_INIT_AUTOMAKE([foreign subdir-objects])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CXXFLAGS="$CXXFLAGS -O0"
	fi
])

PKG_CHECK_MODULES(QT, Qt5Core Qt5Gui Qt5Xml Qt5Network Qt5Qml Qt5DBus Qt5Widgets, dummy=yes,
						AC_MSG_ERROR(Qt is required))

# Needed for qOverload
CXXFLAGS="$CXXFLAGS --std=gnu++14"

AC_SUBST(QT_CFLAGS)
AC_SUBST(QT_LIBS)

AC_MSG_CHECKING(for Qt5 host_bins)
PKG_CHECK_VAR(QMAKE_PATH_HOST_BINS, Qt5Core, host_bins)
AC_SUBST(QMAKE_PATH_HOST_BINS)
AC_MSG_RESULT($QMAKE_PATH_HOST_BINS)

AC_MSG_CHECKING(for moc)
MOC="$QMAKE_PATH_HOST_BINS/moc"
AC_SUBST(MOC)
AC_MSG_RESULT($MOC)

AC_MSG_CHECKING(for uic)
UIC="$QMAKE_PATH_HOST_BINS/uic"
AC_SUBST(UIC)
AC_MSG_RESULT($UIC)

AC_OUTPUT(Makefile)
