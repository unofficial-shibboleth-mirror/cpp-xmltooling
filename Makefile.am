ACLOCAL_AMFLAGS = -I m4

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

SUBDIRS = doc schemas @PACKAGE_NAME@

if BUILD_UNITTEST
SUBDIRS += xmltoolingtest
endif

if DX_COND_doc
all-local: doxygen-doc
else
all-local:
endif

pkgconfig_DATA = @PACKAGE_NAME@.pc @PACKAGE_NAME@-lite.pc

EXTRA_DIST = $(DX_CONFIG) \
	Projects \
	config_win32.h
