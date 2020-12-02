# Process this file with autoreconf
AC_PREREQ([2.50])
AC_INIT([xmltooling],[3.2.0],[https://issues.shibboleth.net/],[xmltooling])
AC_CONFIG_SRCDIR(xmltooling)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE([foreign dist-bzip2 dist-zip subdir-objects nostdinc])
PKG_INSTALLDIR

# Doxygen features
DX_HTML_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(xmltooling, doxygen.cfg, doc/api)

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Produce debug variant (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    AM_CFLAGS="-D_DEBUG"
    AM_CXXFLAGS="-D_DEBUG"
fi

AC_CONFIG_HEADERS([config.h xmltooling/config_pub.h])
AC_CONFIG_FILES([xmltooling.spec xmltooling.pc xmltooling-lite.pc])
AC_CONFIG_FILES([Makefile xmltooling/Makefile xmltoolingtest/Makefile schemas/Makefile doc/Makefile])

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])

if test "$GCC" = "yes" ; then
    AM_CFLAGS="$AM_CFLAGS -Wall -W"
    AM_CXXFLAGS="$AM_CXXFLAGS -Wall -W"
fi

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])

LT_INIT([disable-static])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_DIRENT

# Checks for library functions.
AC_CHECK_FUNCS([strchr strdup strstr timegm gmtime_r strcasecmp])
AC_CHECK_HEADERS([dlfcn.h])
AX_SAVE_FLAGS
LIBS=""
AC_SEARCH_LIBS([dlopen],[dl],,[AC_MSG_ERROR([cannot find dlopen() function])])
AC_SUBST([dlopen_LIBS],[$LIBS])
AX_RESTORE_FLAGS

# checks for pthreads
AX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
if test $enable_threads != "pthread"; then
    AC_MSG_ERROR([unable to find pthreads, currently this is required])
else
    AC_DEFINE([HAVE_PTHREAD],[1],[Define if you have POSIX threads libraries and header files.])
    AX_SAVE_FLAGS
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    AC_CHECK_FUNCS([pthread_rwlock_init])
    AX_RESTORE_FLAGS
fi

AM_CONDITIONAL(BUILD_PTHREAD,test "$enable_threads" = "pthread")

AC_LANG([C++])

# C++ requirements
AC_CXX_NAMESPACES
AC_CXX_REQUIRE_STL

# Boost
BOOST_REQUIRE
BOOST_BIND
BOOST_CONVERSION
BOOST_LAMBDA
BOOST_POINTER_CONTAINER
BOOST_SMART_PTR
BOOST_STRING_ALGO
BOOST_TOKENIZER

# are covariant methods allowed?
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[]],
        [[
        class base { public: virtual base *GetPtr( void ) { return this; } };
        class derived: virtual public base { public: virtual derived *GetPtr( void ) { return this; } };
        ]])],
    [AC_DEFINE([HAVE_COVARIANT_RETURNS],[1],[Define to 1 if C++ compiler supports covariant virtual methods.])])

# is nullptr supported?
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <cstddef>]],[[const char* ptr = nullptr;]])],
    [AC_DEFINE([HAVE_NULLPTR],[1],[Define to 1 if C++ compiler supports nullptr keyword.])])

AX_PKG_CHECK_MODULES([log4shib],,[log4shib],
    [AC_DEFINE([XMLTOOLING_LOG4SHIB],[1],[Define to 1 if log4shib library is used.])],
    [AX_PKG_CHECK_MODULES([log4cpp],,[log4cpp >= 1],
        [AC_DEFINE([XMLTOOLING_LOG4CPP],[1],[Define to 1 if log4cpp library is used.])
	 AC_MSG_WARN([using log4cpp, note that most non-Internet2 supplied versions are not thread-safe])],,
        [XMLTOOLING_LITE_REQUIRES],[XMLTOOLING_LITE_REQUIRES_PRIVATE])],,
    [XMLTOOLING_LITE_REQUIRES],[XMLTOOLING_LITE_REQUIRES_PRIVATE])

AX_PKG_CHECK_MODULES([xerces],,[xerces-c >= 3.2],,,
    [XMLTOOLING_LITE_REQUIRES],[XMLTOOLING_LITE_REQUIRES_PRIVATE])

AX_PKG_CHECK_MODULES([zlib],,[zlib],,,
    [XMLTOOLING_LITE_REQUIRES],[XMLTOOLING_LITE_REQUIRES_PRIVATE])

AC_ARG_WITH(xmlsec,
    AS_HELP_STRING([--with-xmlsec],
        [include signature/encryption support via Apache Santuario (XML Security) @<:@default=check@:>@]),,
    [with_xmlsec=check])

AC_DEFUN([XMLSEC_PKG_CHECK],[
AX_PKG_CHECK_MODULES([$1],,[$2],[$3],
        [AS_IF([test "x$with_xmlsec" = xcheck],
             [AC_MSG_WARN([xmlsec disabled, building without signature/encryption support])
              AC_DEFINE([XMLTOOLING_NO_XMLSEC],[1],
                  [Define to 1 if you wish to disable XML-Security-dependent features.])],
             [AC_MSG_FAILURE([--with-xmlsec was given, but the package was not found])])
        ],[XMLTOOLING_REQUIRES],[XMLTOOLING_REQUIRES_PRIVATE])
])

AS_IF([test "x$with_xmlsec" != xno],
     [XMLSEC_PKG_CHECK([openssl],[openssl],
      [XMLSEC_PKG_CHECK([libcurl],[libcurl],
       [AX_SAVE_FLAGS
        CXXFLAGS="$libcurl_CFLAGS $CXXFLAGS"
        LIBS="libcurl_LIBS $LIBS"
        AC_CHECK_DECLS([CURLOPT_ACCEPT_ENCODING,CURLINFO_TLS_SSL_PTR],,,[[#include <curl/curl.h>]])
        AC_CHECK_DECL([CURLOPT_SSL_CTX_FUNCTION],,[AC_MSG_ERROR([need libcurl that supports CURLOPT_SSL_CTX_FUNCTION])],[[#include <curl/curl.h>]])
        AC_CHECK_TYPE([curl_off_t],[AC_DEFINE([HAVE_CURL_OFF_T],[1],[Define to 1 if you have the 'curl_off_t' type.])],,[[#include <curl/curl.h>]])
        AX_RESTORE_FLAGS
        XMLSEC_PKG_CHECK([xml_security],[xml-security-c >= 2],
	[AC_SUBST([XMLSEC_CFLAGS],["$xml_security_CFLAGS $libcurl_CFLAGS $openssl_CFLAGS"])
	 AC_SUBST([XMLSEC_LIBS],["$xml_security_LIBS $libcurl_LIBS $openssl_LIBS"])
        ])
       ])
     ])
    ])

AM_CONDITIONAL(BUILD_XMLSEC,test "x$XMLSEC_LIBS" != x)

# Does the STL in use help or screw us?
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <string>]],[[std::basic_string<unsigned short> foo; foo=foo+(unsigned short)65]])],
    [AC_DEFINE([HAVE_GOOD_STL],[1],[Define to 1 if you have an STL implementation that supports useful string specialization.])],[])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <vector>]],[[std::iterator_traits<std::vector<int>::iterator>::value_type foo=0]])],
    [AC_DEFINE([HAVE_ITERATOR_TRAITS],[1],[Define to 1 if you have an STL implementation that supports std::iterator_traits.])],[])

# Check for unit test support
AC_ARG_VAR([CXXTEST], [override the cxxtestgen executable and options])
AC_CHECK_PROGS([CXXTEST], [cxxtestgen cxxtestgen.pl], [false])
AC_ARG_VAR([CXXTESTFLAGS], [override the cxxtest compiler flags needed to build tests])
AM_CONDITIONAL([BUILD_UNITTEST], [test "x${CXXTEST}" != xfalse])

AC_ARG_WITH([pkgxmldir],
    AS_HELP_STRING([--with-pkgxmldir=DIR],
        [where to install the schema files @<:@default=${datadir}/xml/AC_PACKAGE_TARNAME@:>@])],
    [],[with_pkgxmldir=${datadir}/xml/AC_PACKAGE_TARNAME])
AC_SUBST([pkgxmldir],[${with_pkgxmldir}])

# output packaging and makefiles
AC_OUTPUT
