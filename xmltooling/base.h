/*
 *  Copyright 2001-2008 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file xmltooling/base.h
 *
 * Base header file definitions
 * Must be included prior to including any other header
 */

#ifndef __xmltooling_base_h__
#define __xmltooling_base_h__

#include <typeinfo>

/* Required for sprintf, used by integer XML attribute macros. */
#include <cstdio>

#if defined (_MSC_VER) || defined(__BORLANDC__)
  #include <xmltooling/config_pub_win32.h>
#else
  #include <xmltooling/config_pub.h>
#endif

#ifdef XMLTOOLING_LITE
# define XMLTOOLING_NO_XMLSEC 1
#endif

#ifdef XMLTOOLING_NO_XMLSEC
# ifdef XMLTOOLING_XERCESC_64BITSAFE
#   include <xercesc/util/XercesDefs.hpp>
    typedef XMLSize_t xsecsize_t;
# else
    typedef unsigned int xsecsize_t;
# endif
#endif

// Windows and GCC4 Symbol Visibility Macros
#ifdef WIN32
  #define XMLTOOL_IMPORT __declspec(dllimport)
  #define XMLTOOL_EXPORT __declspec(dllexport)
  #define XMLTOOL_DLLLOCAL
  #define XMLTOOL_DLLPUBLIC
#else
  #define XMLTOOL_IMPORT
  #ifdef GCC_HASCLASSVISIBILITY
    #define XMLTOOL_EXPORT __attribute__ ((visibility("default")))
    #define XMLTOOL_DLLLOCAL __attribute__ ((visibility("hidden")))
    #define XMLTOOL_DLLPUBLIC __attribute__ ((visibility("default")))
  #else
    #define XMLTOOL_EXPORT
    #define XMLTOOL_DLLLOCAL
    #define XMLTOOL_DLLPUBLIC
  #endif
#endif

// Define XMLTOOL_API for DLL builds
#ifdef XMLTOOLING_EXPORTS
  #define XMLTOOL_API XMLTOOL_EXPORT
#else
  #define XMLTOOL_API XMLTOOL_IMPORT
#endif

// Throwable classes must always be visible on GCC in all binaries
#ifdef WIN32
  #define XMLTOOL_EXCEPTIONAPI(api) api
#elif defined(GCC_HASCLASSVISIBILITY)
  #define XMLTOOL_EXCEPTIONAPI(api) XMLTOOL_EXPORT
#else
  #define XMLTOOL_EXCEPTIONAPI(api)
#endif

#ifdef _MSC_VER
    #define XMLTOOLING_DOXYGEN(desc) /##** desc */
#else
    #define XMLTOOLING_DOXYGEN(desc)
#endif

/**
 * Blocks copy c'tor and assignment operator for a class.
 */
#define MAKE_NONCOPYABLE(type) \
    private: \
        type(const type&); \
        type& operator=(const type&)

#ifndef DOXYGEN_SKIP
#ifndef NULL
#define NULL    0
#endif
#define UNICODE_LITERAL_1(a) {xercesc::chLatin_##a, xercesc::chNull}
#define UNICODE_LITERAL_2(a,b) {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chNull}
#define UNICODE_LITERAL_3(a,b,c) {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chNull}
#define UNICODE_LITERAL_4(a,b,c,d) {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chNull}
#define UNICODE_LITERAL_5(a,b,c,d,e) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chNull}
#define UNICODE_LITERAL_6(a,b,c,d,e,f) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chNull}
#define UNICODE_LITERAL_7(a,b,c,d,e,f,g) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chNull}
#define UNICODE_LITERAL_8(a,b,c,d,e,f,g,h) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chNull}
#define UNICODE_LITERAL_9(a,b,c,d,e,f,g,h,i) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, xercesc::chNull}
#define UNICODE_LITERAL_10(a,b,c,d,e,f,g,h,i,j) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chNull}
#define UNICODE_LITERAL_11(a,b,c,d,e,f,g,h,i,j,k) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chNull}
#define UNICODE_LITERAL_12(a,b,c,d,e,f,g,h,i,j,k,l) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chNull}
#define UNICODE_LITERAL_13(a,b,c,d,e,f,g,h,i,j,k,l,m) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chNull}
#define UNICODE_LITERAL_14(a,b,c,d,e,f,g,h,i,j,k,l,m,n) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chNull}
#define UNICODE_LITERAL_15(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chNull}
#define UNICODE_LITERAL_16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chNull}
#define UNICODE_LITERAL_17(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chNull}
#define UNICODE_LITERAL_18(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, xercesc::chNull}
#define UNICODE_LITERAL_19(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chNull}
#define UNICODE_LITERAL_20(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chNull}
#define UNICODE_LITERAL_21(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chNull}
#define UNICODE_LITERAL_22(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chNull}
#define UNICODE_LITERAL_23(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chNull}
#define UNICODE_LITERAL_24(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chNull}
#define UNICODE_LITERAL_25(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chNull}
#define UNICODE_LITERAL_26(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, xercesc::chNull}
#define UNICODE_LITERAL_27(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chNull}
#define UNICODE_LITERAL_28(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chNull}
#define UNICODE_LITERAL_29(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb,cc) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chLatin_##cc, xercesc::chNull}
#define UNICODE_LITERAL_30(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb,cc,dd) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chLatin_##cc, xercesc::chLatin_##dd, xercesc::chNull}
#define UNICODE_LITERAL_31(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb,cc,dd,ee) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chLatin_##cc, xercesc::chLatin_##dd, xercesc::chLatin_##ee, xercesc::chNull}
#define UNICODE_LITERAL_32(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb,cc,dd,ee,ff) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chLatin_##cc, xercesc::chLatin_##dd, xercesc::chLatin_##ee, xercesc::chLatin_##ff, xercesc::chNull}
#define UNICODE_LITERAL_33(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb,cc,dd,ee,ff,gg) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chLatin_##cc, xercesc::chLatin_##dd, xercesc::chLatin_##ee, xercesc::chLatin_##ff, xercesc::chLatin_##gg, xercesc::chNull}
#define UNICODE_LITERAL_34(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,aa,bb,cc,dd,ee,ff,gg,hh) \
    {xercesc::chLatin_##a, xercesc::chLatin_##b, xercesc::chLatin_##c, xercesc::chLatin_##d, xercesc::chLatin_##e, xercesc::chLatin_##f, xercesc::chLatin_##g, xercesc::chLatin_##h, xercesc::chLatin_##i, \
        xercesc::chLatin_##j, xercesc::chLatin_##k, xercesc::chLatin_##l, xercesc::chLatin_##m, xercesc::chLatin_##n, xercesc::chLatin_##o, xercesc::chLatin_##p, xercesc::chLatin_##q, xercesc::chLatin_##r, \
        xercesc::chLatin_##s, xercesc::chLatin_##t, xercesc::chLatin_##u, xercesc::chLatin_##v, xercesc::chLatin_##w, xercesc::chLatin_##x, xercesc::chLatin_##y, xercesc::chLatin_##z, \
        xercesc::chLatin_##aa, xercesc::chLatin_##bb, xercesc::chLatin_##cc, xercesc::chLatin_##dd, xercesc::chLatin_##ee, xercesc::chLatin_##ff, xercesc::chLatin_##gg, xercesc::chLatin_##hh, xercesc::chNull}
#endif /* DOXYGEN_SKIP */

/**
 * Begins the declaration of an XMLObject specialization for an abstract element/type.
 * Basic boilerplate includes a protected constructor, empty virtual destructor,
 * and Unicode constants for the default associated element's name and prefix.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the class to declare
 * @param base      the base class to derive from using public virtual inheritance
 * @param desc      documentation comment for class
 */
#define DECL_XMLOBJECT_ABSTRACT(linkage,cname,base,desc) \
    XMLTOOLING_DOXYGEN(desc) \
    class linkage cname : public virtual base { \
    protected: \
        cname() {} \
    public: \
        virtual ~cname() {} \
        XMLTOOLING_DOXYGEN(Element local name) \
        static const XMLCh LOCAL_NAME[]; \
    }

/**
 * Begins the declaration of an XMLObject specialization.
 * Basic boilerplate includes a protected constructor, empty virtual destructor,
 * and Unicode constants for the default associated element's name and prefix.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the class to declare
 * @param base      the base class to derive from using public virtual inheritance
 * @param desc      documentation comment for class
 */
#define BEGIN_XMLOBJECT(linkage,cname,base,desc) \
    XMLTOOLING_DOXYGEN(desc) \
    class linkage cname : public virtual base { \
    protected: \
        cname() {} \
    public: \
        virtual ~cname() {} \
        XMLTOOLING_DOXYGEN(Type-specific clone method.) \
        virtual cname* clone##cname() const=0; \
        XMLTOOLING_DOXYGEN(Element local name) \
        static const XMLCh LOCAL_NAME[]

/**
 * Begins the declaration of an XMLObject specialization with two base classes.
 * Basic boilerplate includes a protected constructor, empty virtual destructor,
 * and Unicode constants for the default associated element's name and prefix.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the class to declare
 * @param base      the first base class to derive from using public virtual inheritance
 * @param base2     the second base class to derive from using public virtual inheritance
 * @param desc      documentation comment for class
 */
#define BEGIN_XMLOBJECT2(linkage,cname,base,base2,desc) \
    XMLTOOLING_DOXYGEN(desc) \
    class linkage cname : public virtual base, public virtual base2 { \
    protected: \
        cname() {} \
    public: \
        virtual ~cname() {} \
        XMLTOOLING_DOXYGEN(Type-specific clone method.) \
        virtual cname* clone##cname() const=0; \
        XMLTOOLING_DOXYGEN(Element local name) \
        static const XMLCh LOCAL_NAME[]

/**
 * Begins the declaration of an XMLObject specialization with three base classes.
 * Basic boilerplate includes a protected constructor, empty virtual destructor,
 * and Unicode constants for the default associated element's name and prefix.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the class to declare
 * @param base      the first base class to derive from using public virtual inheritance
 * @param base2     the second base class to derive from using public virtual inheritance
 * @param base3     the third base class to derive from using public virtual inheritance
 * @param desc      documentation comment for class
 */
#define BEGIN_XMLOBJECT3(linkage,cname,base,base2,base3,desc) \
    XMLTOOLING_DOXYGEN(desc) \
    class linkage cname : public virtual base, public virtual base2, public virtual base3 { \
    protected: \
        cname() {} \
    public: \
        virtual ~cname() {} \
        XMLTOOLING_DOXYGEN(Type-specific clone method.) \
        virtual cname* clone##cname() const=0; \
        XMLTOOLING_DOXYGEN(Element local name) \
        static const XMLCh LOCAL_NAME[]

/**
 * Begins the declaration of an XMLObject specialization with four base classes.
 * Basic boilerplate includes a protected constructor, empty virtual destructor,
 * and Unicode constants for the default associated element's name and prefix.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the class to declare
 * @param base      the first base class to derive from using public virtual inheritance
 * @param base2     the second base class to derive from using public virtual inheritance
 * @param base3     the third base class to derive from using public virtual inheritance
 * @param base4     the fourth base class to derive from using public virtual inheritance
 * @param desc      documentation comment for class
 */
#define BEGIN_XMLOBJECT4(linkage,cname,base,base2,base3,base4,desc) \
    XMLTOOLING_DOXYGEN(desc) \
    class linkage cname : public virtual base, public virtual base2, public virtual base3, public virtual base4 { \
    protected: \
        cname() {} \
    public: \
        virtual ~cname() {} \
        XMLTOOLING_DOXYGEN(Type-specific clone method.) \
        virtual cname* clone##cname() const=0; \
        XMLTOOLING_DOXYGEN(Element local name) \
        static const XMLCh LOCAL_NAME[]

/**
 * Begins the declaration of an XMLObject specialization with five base classes.
 * Basic boilerplate includes a protected constructor, empty virtual destructor,
 * and Unicode constants for the default associated element's name and prefix.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the class to declare
 * @param base      the first base class to derive from using public virtual inheritance
 * @param base2     the second base class to derive from using public virtual inheritance
 * @param base3     the third base class to derive from using public virtual inheritance
 * @param base4     the fourth base class to derive from using public virtual inheritance
 * @param base5     the fifth base class to derive from using public virtual inheritance
 * @param desc      documentation comment for class
 */
#define BEGIN_XMLOBJECT5(linkage,cname,base,base2,base3,base4,base5,desc) \
    XMLTOOLING_DOXYGEN(desc) \
    class linkage cname : public virtual base, public virtual base2, public virtual base3, public virtual base4, public virtual base5 { \
    protected: \
        cname() {} \
    public: \
        virtual ~cname() {} \
        XMLTOOLING_DOXYGEN(Type-specific clone method.) \
        virtual cname* clone##cname() const=0; \
        XMLTOOLING_DOXYGEN(Element local name) \
        static const XMLCh LOCAL_NAME[]

/**
 * Ends the declaration of an XMLObject specialization.
 */
#define END_XMLOBJECT }

/**
 * Declares a static variable holding the XMLObject's element QName.
 */
#define DECL_ELEMENT_QNAME \
    public: \
        XMLTOOLING_DOXYGEN(Element QName) \
        static xmltooling::QName ELEMENT_QNAME

/**
 * Declares a static variable holding the XMLObject's schema type QName.
 */
#define DECL_TYPE_QNAME \
    public: \
        XMLTOOLING_DOXYGEN(Type QName) \
        static xmltooling::QName TYPE_QNAME

/**
 * Implements a static variable holding an XMLObject's element QName.
 *
 * @param cname             the name of the XMLObject specialization
 * @param namespaceURI      the XML namespace of the default associated element
 * @param namespacePrefix   the XML namespace prefix of the default associated element
 */
#define IMPL_ELEMENT_QNAME(cname,namespaceURI,namespacePrefix) \
    xmltooling::QName cname::ELEMENT_QNAME(namespaceURI,cname::LOCAL_NAME,namespacePrefix)

/**
 * Implements a static variable holding an XMLObject's schema type QName.
 *
 * @param cname             the name of the XMLObject specialization
 * @param namespaceURI      the XML namespace of the default associated element
 * @param namespacePrefix   the XML namespace prefix of the default associated element
 */
#define IMPL_TYPE_QNAME(cname,namespaceURI,namespacePrefix) \
    xmltooling::QName cname::TYPE_QNAME(namespaceURI,cname::TYPE_NAME,namespacePrefix)

/**
 * Declares abstract set method for a typed XML attribute.
 * The get method is omitted.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 * @param type      the attribute's data type
 */
#define DECL_INHERITED_XMLOBJECT_ATTRIB(proper,upcased,type) \
    public: \
        XMLTOOLING_DOXYGEN(proper attribute name) \
        static const XMLCh upcased##_ATTRIB_NAME[]; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
        virtual void set##proper(const type* proper)=0

/**
 * Declares abstract get/set methods for a typed XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 * @param type      the attribute's data type
 */
#define DECL_XMLOBJECT_ATTRIB(proper,upcased,type) \
    public: \
        XMLTOOLING_DOXYGEN(proper attribute name) \
        static const XMLCh upcased##_ATTRIB_NAME[]; \
        XMLTOOLING_DOXYGEN(Returns the proper attribute.) \
        virtual const type* get##proper() const=0; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
        virtual void set##proper(const type* proper)=0

/**
 * Declares abstract set method for a string XML attribute.
 * The get method is omitted.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 */
#define DECL_INHERITED_STRING_ATTRIB(proper,upcased) \
    DECL_INHERITED_XMLOBJECT_ATTRIB(proper,upcased,XMLCh)

/**
 * Declares abstract get/set methods for a string XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 */
#define DECL_STRING_ATTRIB(proper,upcased) \
    DECL_XMLOBJECT_ATTRIB(proper,upcased,XMLCh)

/**
 * Declares abstract set method for a DateTime XML attribute.
 * The get method is omitted.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 */
#define DECL_INHERITED_DATETIME_ATTRIB(proper,upcased) \
    DECL_INHERITED_XMLOBJECT_ATTRIB(proper,upcased,xmltooling::DateTime); \
    XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
    virtual void set##proper(time_t proper)=0; \
    XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
    virtual void set##proper(const XMLCh* proper)=0

/**
 * Declares abstract get/set methods for a DateTime XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 */
#define DECL_DATETIME_ATTRIB(proper,upcased) \
    DECL_XMLOBJECT_ATTRIB(proper,upcased,xmltooling::DateTime); \
    XMLTOOLING_DOXYGEN(Returns the proper attribute in epoch form.) \
    virtual time_t get##proper##Epoch() const=0; \
    XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
    virtual void set##proper(time_t proper)=0; \
    XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
    virtual void set##proper(const XMLCh* proper)=0

/**
 * Declares abstract set method for an integer XML attribute.
 * The get method is omitted.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 */
#define DECL_INHERITED_INTEGER_ATTRIB(proper,upcased) \
    public: \
        XMLTOOLING_DOXYGEN(proper attribute name) \
        static const XMLCh upcased##_ATTRIB_NAME[]; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute using a string value.) \
        virtual void set##proper(const XMLCh* proper)=0; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
        virtual void set##proper(int proper)=0

/**
 * Declares abstract get/set methods for an integer XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 */
#define DECL_INTEGER_ATTRIB(proper,upcased) \
    public: \
        XMLTOOLING_DOXYGEN(proper attribute name) \
        static const XMLCh upcased##_ATTRIB_NAME[]; \
        XMLTOOLING_DOXYGEN(Returns the proper attribute after a NULL indicator.) \
        virtual std::pair<bool,int> get##proper() const=0; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute using a string value.) \
        virtual void set##proper(const XMLCh* proper)=0; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
        virtual void set##proper(int proper)=0

/**
 * Declares abstract get/set methods for a boolean XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param upcased   the upcased name of the attribute
 * @param def       the default/presumed value, if no explicit value has been set
 */
#define DECL_BOOLEAN_ATTRIB(proper,upcased,def) \
    public: \
        XMLTOOLING_DOXYGEN(proper attribute name) \
        static const XMLCh upcased##_ATTRIB_NAME[]; \
        XMLTOOLING_DOXYGEN(Returns the proper attribute or def if not set.) \
        bool proper() const { \
            switch (get##proper()) { \
                case xmlconstants::XML_BOOL_TRUE: \
                case xmlconstants::XML_BOOL_ONE: \
                    return true; \
                case xmlconstants::XML_BOOL_FALSE: \
                case xmlconstants::XML_BOOL_ZERO: \
                    return false; \
                default: \
                    return def; \
            } \
        } \
        XMLTOOLING_DOXYGEN(Returns the proper attribute as an explicit enumerated value.) \
        virtual xmlconstants::xmltooling_bool_t get##proper() const=0; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute using an enumerated value.) \
        virtual void proper(xmlconstants::xmltooling_bool_t value)=0; \
        XMLTOOLING_DOXYGEN(Sets the proper attribute.) \
        void proper(bool value) { \
            proper(value ? xmlconstants::XML_BOOL_ONE : xmlconstants::XML_BOOL_ZERO); \
        } \
        XMLTOOLING_DOXYGEN(Sets the proper attribute using a string constant.) \
        void set##proper(const XMLCh* value) { \
            if (value) { \
                switch (*value) { \
                    case xercesc::chLatin_t: \
                        proper(xmlconstants::XML_BOOL_TRUE); \
                        break; \
                    case xercesc::chLatin_f: \
                        proper(xmlconstants::XML_BOOL_FALSE); \
                        break; \
                    case xercesc::chDigit_1: \
                        proper(xmlconstants::XML_BOOL_ONE); \
                        break; \
                    case xercesc::chDigit_0: \
                        proper(xmlconstants::XML_BOOL_ZERO); \
                        break; \
                    default: \
                        proper(xmlconstants::XML_BOOL_NULL); \
                } \
            } \
            else \
                proper(xmlconstants::XML_BOOL_NULL); \
        }

/**
 * Implements get/set methods and a private member for a typed XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param type      the attribute's data type
 */
#define IMPL_XMLOBJECT_ATTRIB(proper,type) \
    protected: \
        type* m_##proper; \
    public: \
        const type* get##proper() const { \
            return m_##proper; \
        } \
        void set##proper(const type* proper) { \
            m_##proper = prepareForAssignment(m_##proper,proper); \
        }

/**
 * Implements get/set methods and a private member for a string XML attribute.
 *
 * @param proper    the proper name of the attribute
 */
#define IMPL_STRING_ATTRIB(proper) \
    IMPL_XMLOBJECT_ATTRIB(proper,XMLCh)

/**
 * Implements get/set methods and a private member for a string XML attribute,
 * plus a getXMLID override.
 *
 * @param proper    the proper name of the attribute
 */
#define IMPL_ID_ATTRIB(proper) \
    IMPL_XMLOBJECT_ATTRIB(proper,XMLCh) \
    const XMLCh* getXMLID() const { \
        return m_##proper; \
    }

/**
 * Implements get/set methods and a private member for a DateTime XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param fallback  epoch to return when attribute is NULL
 */
#define IMPL_DATETIME_ATTRIB(proper,fallback) \
    IMPL_DATETIME_ATTRIB_EX(proper,fallback,false)

/**
 * Implements get/set methods and a private member for a duration-valued DateTime XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param fallback  epoch to return when attribute is NULL
 */
#define IMPL_DURATION_ATTRIB(proper,fallback) \
    IMPL_DATETIME_ATTRIB_EX(proper,fallback,true)

/**
 * Implements get/set methods and a private member for a DateTime XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param fallback  epoch to return when attribute is NULL
 * @param duration  true iff the attribute should be handled as a duration
 */
#define IMPL_DATETIME_ATTRIB_EX(proper,fallback,duration) \
    protected: \
        DateTime* m_##proper; \
        time_t m_##proper##Epoch; \
    public: \
        const DateTime* get##proper() const { \
            return m_##proper; \
        } \
        time_t get##proper##Epoch() const { \
            return m_##proper ? m_##proper##Epoch : fallback; \
        } \
        void set##proper(const DateTime* proper) { \
            m_##proper = prepareForAssignment(m_##proper,proper); \
            if (m_##proper) \
                m_##proper##Epoch=m_##proper->getEpoch(duration); \
        } \
        void set##proper(time_t proper) { \
            m_##proper = prepareForAssignment(m_##proper,proper,duration); \
            m_##proper##Epoch = proper; \
        } \
        void set##proper(const XMLCh* proper) { \
            m_##proper = prepareForAssignment(m_##proper,proper,duration); \
            if (m_##proper) \
                m_##proper##Epoch=m_##proper->getEpoch(duration); \
        }

/**
 * Implements get/set methods and a private member for an integer XML attribute.
 *
 * @param proper    the proper name of the attribute
 */
#define IMPL_INTEGER_ATTRIB(proper) \
    protected: \
        XMLCh* m_##proper; \
    public: \
        pair<bool,int> get##proper() const { \
            return make_pair((m_##proper!=NULL),(m_##proper!=NULL ? xercesc::XMLString::parseInt(m_##proper): 0)); \
        } \
        void set##proper(const XMLCh* proper) { \
            m_##proper = prepareForAssignment(m_##proper,proper); \
        } \
        void set##proper(int proper) { \
            char buf##proper[64]; \
            sprintf(buf##proper,"%d",proper); \
            auto_ptr_XMLCh wide##proper(buf##proper); \
            set##proper(wide##proper.get()); \
        }

/**
 * Implements get/set methods and a private member for a boolean XML attribute.
 *
 * @param proper    the proper name of the attribute
 */
#define IMPL_BOOLEAN_ATTRIB(proper) \
    protected: \
        xmlconstants::xmltooling_bool_t m_##proper; \
    public: \
        xmlconstants::xmltooling_bool_t get##proper() const { \
            return m_##proper; \
        } \
        void proper(xmlconstants::xmltooling_bool_t value) { \
            if (m_##proper != value) { \
                releaseThisandParentDOM(); \
                m_##proper = value; \
            } \
        }

/**
 * Implements get/set methods and a private member for a typed, qualified XML attribute.
 *
 * @param proper    the proper name of the attribute
 * @param type      the attribute's data type
 */
#define IMPL_XMLOBJECT_FOREIGN_ATTRIB(proper,type) \
    protected: \
    XMLCh* m_##proper##Prefix; \
        type* m_##proper; \
    public: \
        const type* get##proper() const { \
            return m_##proper; \
        } \
        void set##proper(const type* proper) { \
            m_##proper = prepareForAssignment(m_##proper,proper); \
            XMLString::release(&m_##proper##Prefix); \
            m_##proper##Prefix = NULL; \
        }

/**
 * Declares abstract set method for a typed XML child object in a foreign namespace.
 * The get method is omitted.
 *
 * @param proper    the proper name of the child type
 * @param ns        the C++ namespace for the type
 */
#define DECL_INHERITED_TYPED_FOREIGN_CHILD(proper,ns) \
    public: \
        XMLTOOLING_DOXYGEN(Sets the proper child.) \
        virtual void set##proper(ns::proper* child)=0

/**
 * Declares abstract get/set methods for a typed XML child object in a foreign namespace.
 *
 * @param proper    the proper name of the child type
 * @param ns        the C++ namespace for the type
 */
#define DECL_TYPED_FOREIGN_CHILD(proper,ns) \
    public: \
        XMLTOOLING_DOXYGEN(Returns the proper child.) \
        virtual ns::proper* get##proper() const=0; \
        XMLTOOLING_DOXYGEN(Sets the proper child.) \
        virtual void set##proper(ns::proper* child)=0

/**
 * Declares abstract set method for a typed XML child object.
 * The get method is omitted.
 *
 * @param proper    the proper name of the child type
 */
#define DECL_INHERITED_TYPED_CHILD(proper) \
    public: \
        XMLTOOLING_DOXYGEN(Sets the proper child.) \
        virtual void set##proper(proper* child)=0

/**
 * Declares abstract get/set methods for a typed XML child object.
 *
 * @param proper    the proper name of the child type
 */
#define DECL_TYPED_CHILD(proper) \
    public: \
        XMLTOOLING_DOXYGEN(Returns the proper child.) \
        virtual proper* get##proper() const=0; \
        XMLTOOLING_DOXYGEN(Sets the proper child.) \
        virtual void set##proper(proper* child)=0

/**
 * Declares abstract get/set methods for a generic XML child object.
 *
 * @param proper    the proper name of the child
 */
#define DECL_XMLOBJECT_CHILD(proper) \
    public: \
        XMLTOOLING_DOXYGEN(Returns the proper child.) \
        virtual xmltooling::XMLObject* get##proper() const=0; \
        XMLTOOLING_DOXYGEN(Sets the proper child.) \
        virtual void set##proper(xmltooling::XMLObject* child)=0


/**
 * Implements get/set methods and a private list iterator member for a typed XML child object.
 *
 * @param proper    the proper name of the child type
 */
#define IMPL_TYPED_CHILD(proper) \
    protected: \
        proper* m_##proper; \
        std::list<xmltooling::XMLObject*>::iterator m_pos_##proper; \
    public: \
        proper* get##proper() const { \
            return m_##proper; \
        } \
        void set##proper(proper* child) { \
            prepareForAssignment(m_##proper,child); \
            *m_pos_##proper = m_##proper = child; \
        }

/**
 * Implements get/set methods and a private list iterator member for
 * a typed XML child object in a foreign namespace
 *
 * @param proper    the proper name of the child type
 * @param ns        the C++ namespace for the type
 */
#define IMPL_TYPED_FOREIGN_CHILD(proper,ns) \
    protected: \
        ns::proper* m_##proper; \
        std::list<xmltooling::XMLObject*>::iterator m_pos_##proper; \
    public: \
        ns::proper* get##proper() const { \
            return m_##proper; \
        } \
        void set##proper(ns::proper* child) { \
            prepareForAssignment(m_##proper,child); \
            *m_pos_##proper = m_##proper = child; \
        }

/**
 * Implements get/set methods and a private list iterator member for a generic XML child object.
 *
 * @param proper    the proper name of the child
 */
#define IMPL_XMLOBJECT_CHILD(proper) \
    protected: \
        xmltooling::XMLObject* m_##proper; \
        std::list<xmltooling::XMLObject*>::iterator m_pos_##proper; \
    public: \
        xmltooling::XMLObject* get##proper() const { \
            return m_##proper; \
        } \
        void set##proper(xmltooling::XMLObject* child) { \
            prepareForAssignment(m_##proper,child); \
            *m_pos_##proper = m_##proper = child; \
        }

/**
 * Declares abstract get/set methods for a typed XML child collection.
 *
 * @param proper    the proper name of the child type
 */
#define DECL_TYPED_CHILDREN(proper) \
    public: \
        XMLTOOLING_DOXYGEN(Returns modifiable proper collection.) \
        virtual VectorOf(proper) get##proper##s()=0; \
        XMLTOOLING_DOXYGEN(Returns reference to immutable proper collection.) \
        virtual const std::vector<proper*>& get##proper##s() const=0

/**
 * Declares abstract get/set methods for a typed XML child collection in a foreign namespace.
 *
 * @param proper    the proper name of the child type
 * @param ns        the C++ namespace for the type
 */
#define DECL_TYPED_FOREIGN_CHILDREN(proper,ns) \
    public: \
        XMLTOOLING_DOXYGEN(Returns modifiable proper collection.) \
        virtual VectorOf(ns::proper) get##proper##s()=0; \
        XMLTOOLING_DOXYGEN(Returns reference to immutable proper collection.) \
        virtual const std::vector<ns::proper*>& get##proper##s() const=0

/**
 * Declares abstract get/set methods for a generic XML child collection.
 *
 * @param proper    the proper name of the child
 */
#define DECL_XMLOBJECT_CHILDREN(proper) \
    public: \
        XMLTOOLING_DOXYGEN(Returns modifiable proper collection.) \
        virtual VectorOf(xmltooling::XMLObject) get##proper##s()=0; \
        XMLTOOLING_DOXYGEN(Returns reference to immutable proper collection.) \
        virtual const std::vector<xmltooling::XMLObject*>& get##proper##s() const=0

/**
 * Implements get method and a private vector member for a typed XML child collection.
 *
 * @param proper    the proper name of the child type
 * @param fence     insertion fence for new objects of the child collection in backing list
 */
#define IMPL_TYPED_CHILDREN(proper,fence) \
    protected: \
        std::vector<proper*> m_##proper##s; \
    public: \
        VectorOf(proper) get##proper##s() { \
            return VectorOf(proper)(this, m_##proper##s, &m_children, fence); \
        } \
        const std::vector<proper*>& get##proper##s() const { \
            return m_##proper##s; \
        }

/**
 * Implements get method and a private vector member for a typed XML child collection
 * in a foreign namespace.
 *
 * @param proper    the proper name of the child type
 * @param ns        the C++ namespace for the type
 * @param fence     insertion fence for new objects of the child collection in backing list
 */
#define IMPL_TYPED_FOREIGN_CHILDREN(proper,ns,fence) \
    protected: \
        std::vector<ns::proper*> m_##proper##s; \
    public: \
        VectorOf(ns::proper) get##proper##s() { \
            return VectorOf(ns::proper)(this, m_##proper##s, &m_children, fence); \
        } \
        const std::vector<ns::proper*>& get##proper##s() const { \
            return m_##proper##s; \
        }

/**
 * Implements get method and a private vector member for a generic XML child collection.
 *
 * @param proper    the proper name of the child
 * @param fence     insertion fence for new objects of the child collection in backing list
 */
#define IMPL_XMLOBJECT_CHILDREN(proper,fence) \
    protected: \
        std::vector<xmltooling::XMLObject*> m_##proper##s; \
    public: \
        VectorOf(xmltooling::XMLObject) get##proper##s() { \
            return VectorOf(xmltooling::XMLObject)(this, m_##proper##s, &m_children, fence); \
        } \
        const std::vector<xmltooling::XMLObject*>& get##proper##s() const { \
            return m_##proper##s; \
        }

/**
 * Implements marshalling for a string attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define MARSHALL_STRING_ATTRIB(proper,ucase,namespaceURI) \
    if (m_##proper && *m_##proper) { \
        domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, m_##proper); \
    }

/**
 * Implements marshalling for a DateTime attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define MARSHALL_DATETIME_ATTRIB(proper,ucase,namespaceURI) \
    if (m_##proper) { \
        domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, m_##proper->getRawData()); \
    }

/**
 * Implements marshalling for an integer attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define MARSHALL_INTEGER_ATTRIB(proper,ucase,namespaceURI) \
    if (m_##proper && *m_##proper) { \
        domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, m_##proper); \
    }

/**
 * Implements marshalling for a boolean attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define MARSHALL_BOOLEAN_ATTRIB(proper,ucase,namespaceURI) \
    switch (m_##proper) { \
        case xmlconstants::XML_BOOL_TRUE: \
            domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, xmlconstants::XML_TRUE); \
            break; \
        case xmlconstants::XML_BOOL_ONE: \
            domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, xmlconstants::XML_ONE); \
            break; \
        case xmlconstants::XML_BOOL_FALSE: \
            domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, xmlconstants::XML_FALSE); \
            break; \
        case xmlconstants::XML_BOOL_ZERO: \
            domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, xmlconstants::XML_ZERO); \
            break; \
        case xmlconstants::XML_BOOL_NULL: \
            break; \
    }

/**
 * Implements marshalling for a QName attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define MARSHALL_QNAME_ATTRIB(proper,ucase,namespaceURI) \
    if (m_##proper) { \
        auto_ptr_XMLCh qstr(m_##proper->toString().c_str()); \
        domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, qstr.get()); \
    }

#ifdef XMLTOOLING_XERCESC_BOOLSETIDATTRIBUTE
/**
 * Implements marshalling for an ID attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
# define MARSHALL_ID_ATTRIB(proper,ucase,namespaceURI) \
    if (m_##proper && *m_##proper) { \
        domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, m_##proper); \
        domElement->setIdAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, true); \
    }
#else
/**
 * Implements marshalling for an ID attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
# define MARSHALL_ID_ATTRIB(proper,ucase,namespaceURI) \
    if (m_##proper && *m_##proper) { \
        domElement->setAttributeNS(namespaceURI, ucase##_ATTRIB_NAME, m_##proper); \
        domElement->setIdAttributeNS(namespaceURI, ucase##_ATTRIB_NAME); \
    }
#endif

/**
 * Implements unmarshalling process branch for a string attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define PROC_STRING_ATTRIB(proper,ucase,namespaceURI) \
    if (xmltooling::XMLHelper::isNodeNamed(attribute, namespaceURI, ucase##_ATTRIB_NAME)) { \
        set##proper(attribute->getValue()); \
        return; \
    }

#ifdef XMLTOOLING_XERCESC_BOOLSETIDATTRIBUTE
/**
 * Implements unmarshalling process branch for an ID attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
# define PROC_ID_ATTRIB(proper,ucase,namespaceURI) \
    if (xmltooling::XMLHelper::isNodeNamed(attribute, namespaceURI, ucase##_ATTRIB_NAME)) { \
        set##proper(attribute->getValue()); \
        attribute->getOwnerElement()->setIdAttributeNode(attribute, true); \
        return; \
    }
#else
/**
 * Implements unmarshalling process branch for an ID attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
# define PROC_ID_ATTRIB(proper,ucase,namespaceURI) \
    if (xmltooling::XMLHelper::isNodeNamed(attribute, namespaceURI, ucase##_ATTRIB_NAME)) { \
        set##proper(attribute->getValue()); \
        attribute->getOwnerElement()->setIdAttributeNode(attribute); \
        return; \
    }
#endif

/**
 * Implements unmarshalling process branch for a DateTime attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define PROC_DATETIME_ATTRIB(proper,ucase,namespaceURI) \
    PROC_STRING_ATTRIB(proper,ucase,namespaceURI)

/**
 * Implements unmarshalling process branch for a DateTime attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define PROC_QNAME_ATTRIB(proper,ucase,namespaceURI) \
    if (xmltooling::XMLHelper::isNodeNamed(attribute, namespaceURI, ucase##_ATTRIB_NAME)) { \
        set##proper(XMLHelper::getAttributeValueAsQName(attribute)); \
        return; \
    }

/**
 * Implements unmarshalling process branch for an integer attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define PROC_INTEGER_ATTRIB(proper,ucase,namespaceURI) \
    PROC_STRING_ATTRIB(proper,ucase,namespaceURI)

/**
 * Implements unmarshalling process branch for a boolean attribute
 *
 * @param proper        the proper name of the attribute
 * @param ucase         the upcased name of the attribute
 * @param namespaceURI  the XML namespace of the attribute
 */
#define PROC_BOOLEAN_ATTRIB(proper,ucase,namespaceURI) \
    PROC_STRING_ATTRIB(proper,ucase,namespaceURI)

/**
 * Implements unmarshalling process branch for typed child collection element
 *
 * @param proper        the proper name of the child type
 * @param namespaceURI  the XML namespace of the child element
 * @param force         bypass use of hint and just cast down to check child
 */
#define PROC_TYPED_CHILDREN(proper,namespaceURI,force) \
    if (force || xmltooling::XMLHelper::isNodeNamed(root,namespaceURI,proper::LOCAL_NAME)) { \
        proper* typesafe=dynamic_cast<proper*>(childXMLObject); \
        if (typesafe) { \
            get##proper##s().push_back(typesafe); \
            return; \
        } \
    }

/**
 * Implements unmarshalling process branch for typed child collection element
 * in a foreign namespace.
 *
 * @param proper        the proper name of the child type
 * @param ns            the C++ namespace for the type
 * @param namespaceURI  the XML namespace of the child element
 * @param force         bypass use of hint and just cast down to check child
 */
#define PROC_TYPED_FOREIGN_CHILDREN(proper,ns,namespaceURI,force) \
    if (force || xmltooling::XMLHelper::isNodeNamed(root,namespaceURI,ns::proper::LOCAL_NAME)) { \
        ns::proper* typesafe=dynamic_cast<ns::proper*>(childXMLObject); \
        if (typesafe) { \
            get##proper##s().push_back(typesafe); \
            return; \
        } \
    }

/**
 * Implements unmarshalling process branch for typed child singleton element
 *
 * @param proper        the proper name of the child type
 * @param namespaceURI  the XML namespace of the child element
 * @param force         bypass use of hint and just cast down to check child
 */
#define PROC_TYPED_CHILD(proper,namespaceURI,force) \
    if (force || xmltooling::XMLHelper::isNodeNamed(root,namespaceURI,proper::LOCAL_NAME)) { \
        proper* typesafe=dynamic_cast<proper*>(childXMLObject); \
        if (typesafe && !m_##proper) { \
            typesafe->setParent(this); \
            *m_pos_##proper = m_##proper = typesafe; \
            return; \
        } \
    }

/**
 * Implements unmarshalling process branch for typed child singleton element
 * in a foreign namespace.
 *
 * @param proper        the proper name of the child type
 * @param ns            the C++ namespace for the type
 * @param namespaceURI  the XML namespace of the child element
 * @param force         bypass use of hint and just cast down to check child
 */
#define PROC_TYPED_FOREIGN_CHILD(proper,ns,namespaceURI,force) \
    if (force || xmltooling::XMLHelper::isNodeNamed(root,namespaceURI,ns::proper::LOCAL_NAME)) { \
        ns::proper* typesafe=dynamic_cast<ns::proper*>(childXMLObject); \
        if (typesafe && !m_##proper) { \
            typesafe->setParent(this); \
            *m_pos_##proper = m_##proper = typesafe; \
            return; \
        } \
    }

/**
 * Implements unmarshalling process branch for a generic child singleton element
 *
 * @param proper        the proper name of the child type
 * @param namespaceURI  the XML namespace of the child element
 */
#define PROC_XMLOBJECT_CHILD(proper,namespaceURI) \
    if (xmltooling::XMLHelper::isNodeNamed(root,namespaceURI,proper::LOCAL_NAME)) { \
        if (!m_##proper) { \
            childXMLObject->setParent(this); \
            *m_pos_##proper = m_##proper = childXMLObject; \
            return; \
        } \
    }

/**
 * Declares aliased get/set methods for named XML element simple content.
 *
 * @param proper    the proper name to label the element's content
 */
#define DECL_SIMPLE_CONTENT(proper) \
    XMLTOOLING_DOXYGEN(Returns proper.) \
    const XMLCh* get##proper() const { \
        return getTextContent(); \
    } \
    XMLTOOLING_DOXYGEN(Sets or clears proper.) \
    void set##proper(const XMLCh* proper) { \
        setTextContent(proper); \
    }

/**
 * Declares aliased get/set methods for named integer XML element content.
 *
 * @param proper    the proper name to label the element's content
 */
#define DECL_INTEGER_CONTENT(proper) \
    XMLTOOLING_DOXYGEN(Returns proper in integer form after a NULL indicator.) \
    std::pair<bool,int> get##proper() const { \
        return std::make_pair((getTextContent()!=NULL), (getTextContent()!=NULL ? xercesc::XMLString::parseInt(getTextContent()) : 0)); \
    } \
    XMLTOOLING_DOXYGEN(Sets proper.) \
    void set##proper(int proper) { \
        char buf[64]; \
        sprintf(buf,"%d",proper); \
        xmltooling::auto_ptr_XMLCh widebuf(buf); \
        setTextContent(widebuf.get()); \
    } \
    XMLTOOLING_DOXYGEN(Sets or clears proper.) \
    void set##proper(const XMLCh* proper) { \
        setTextContent(proper); \
    }

/**
 * Implements cloning methods for an XMLObject specialization implementation class.
 *
 * @param cname    the name of the XMLObject specialization
 */
#define IMPL_XMLOBJECT_CLONE(cname) \
    cname* clone##cname() const { \
        return dynamic_cast<cname*>(clone()); \
    } \
    xmltooling::XMLObject* clone() const { \
        std::auto_ptr<xmltooling::XMLObject> domClone(xmltooling::AbstractDOMCachingXMLObject::clone()); \
        cname##Impl* ret=dynamic_cast<cname##Impl*>(domClone.get()); \
        if (ret) { \
            domClone.release(); \
            return ret; \
        } \
        return new cname##Impl(*this); \
    }

/**
 * Declares an XMLObject specialization with a simple content model and type,
 * handling it as string data.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the XMLObject specialization
 * @param proper    the proper name to label the element's content
 * @param desc      documentation for class
 */
#define DECL_XMLOBJECT_SIMPLE(linkage,cname,proper,desc) \
    BEGIN_XMLOBJECT(linkage,cname,xmltooling::XMLObject,desc); \
        DECL_SIMPLE_CONTENT(proper); \
    END_XMLOBJECT

/**
 * Declares and defines an implementation class for an XMLObject with
 * a simple content model and type, handling it as string data.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the XMLObject specialization
 */
#define DECL_XMLOBJECTIMPL_SIMPLE(linkage,cname) \
    class linkage cname##Impl \
        : public virtual cname, \
            public xmltooling::AbstractSimpleElement, \
            public xmltooling::AbstractDOMCachingXMLObject, \
            public xmltooling::AbstractXMLObjectMarshaller, \
            public xmltooling::AbstractXMLObjectUnmarshaller \
    { \
    public: \
        virtual ~cname##Impl() {} \
        cname##Impl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType) \
            : xmltooling::AbstractXMLObject(nsURI, localName, prefix, schemaType) { \
        } \
        cname##Impl(const cname##Impl& src) \
            : xmltooling::AbstractXMLObject(src), \
                xmltooling::AbstractSimpleElement(src), \
                xmltooling::AbstractDOMCachingXMLObject(src) {} \
        IMPL_XMLOBJECT_CLONE(cname) \
    }

#ifdef HAVE_COVARIANT_RETURNS

/**
 * Begins the declaration of an XMLObjectBuilder specialization.
 * Basic boilerplate includes an empty virtual destructor, and
 * a default builder that defaults the element name.
 *
 * @param linkage           linkage specifier for the class
 * @param cname             the name of the XMLObject specialization
 * @param namespaceURI      the XML namespace of the default associated element
 * @param namespacePrefix   the XML namespace prefix of the default associated element
 */
#define BEGIN_XMLOBJECTBUILDER(linkage,cname,namespaceURI,namespacePrefix) \
    XMLTOOLING_DOXYGEN(Builder for cname objects.) \
    class linkage cname##Builder : public xmltooling::ConcreteXMLObjectBuilder { \
    public: \
        virtual ~cname##Builder() {} \
        XMLTOOLING_DOXYGEN(Default builder.) \
        virtual cname* buildObject() const { \
            return buildObject(namespaceURI,cname::LOCAL_NAME,namespacePrefix); \
        } \
        XMLTOOLING_DOXYGEN(Builder that allows element/type override.) \
        virtual cname* buildObject( \
            const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL \
            ) const

/**
 * Ends the declaration of an XMLObjectBuilder specialization.
 */
#define END_XMLOBJECTBUILDER }

/**
 * Declares a generic XMLObjectBuilder specialization.
 *
 * @param linkage           linkage specifier for the class
 * @param cname             the name of the XMLObject specialization
 * @param namespaceURI      the XML namespace of the default associated element
 * @param namespacePrefix   the XML namespace prefix of the default associated element
 */
 #define DECL_XMLOBJECTBUILDER(linkage,cname,namespaceURI,namespacePrefix) \
    BEGIN_XMLOBJECTBUILDER(linkage,cname,namespaceURI,namespacePrefix); \
    XMLTOOLING_DOXYGEN(Singleton builder.) \
    static cname* build##cname() { \
        const cname##Builder* b = dynamic_cast<const cname##Builder*>( \
            XMLObjectBuilder::getBuilder(xmltooling::QName(namespaceURI,cname::LOCAL_NAME)) \
            ); \
        if (b) \
            return b->buildObject(); \
        throw xmltooling::XMLObjectException("Unable to obtain typed builder for "#cname"."); \
    } \
    END_XMLOBJECTBUILDER

/**
 * Implements the standard XMLObjectBuilder specialization function.
 *
 * @param cname the name of the XMLObject specialization
 */
#define IMPL_XMLOBJECTBUILDER(cname) \
    cname* cname##Builder::buildObject( \
        const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::QName* schemaType \
        ) const \
    { \
        return new cname##Impl(nsURI,localName,prefix,schemaType); \
    }

#else   /* !HAVE_COVARIANT_RETURNS */

/**
 * Begins the declaration of an XMLObjectBuilder specialization.
 * Basic boilerplate includes an empty virtual destructor, and
 * a default builder that defaults the element name.
 *
 * @param linkage           linkage specifier for the class
 * @param cname             the name of the XMLObject specialization
 * @param namespaceURI      the XML namespace of the default associated element
 * @param namespacePrefix   the XML namespace prefix of the default associated element
 */
#define BEGIN_XMLOBJECTBUILDER(linkage,cname,namespaceURI,namespacePrefix) \
    XMLTOOLING_DOXYGEN(Builder for cname objects.) \
    class linkage cname##Builder : public xmltooling::ConcreteXMLObjectBuilder { \
    public: \
        virtual ~cname##Builder() {} \
        XMLTOOLING_DOXYGEN(Default builder.) \
        virtual xmltooling::XMLObject* buildObject() const { \
            return buildObject(namespaceURI,cname::LOCAL_NAME,namespacePrefix); \
        } \
        XMLTOOLING_DOXYGEN(Builder that allows element/type override.) \
        virtual xmltooling::XMLObject* buildObject( \
            const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL \
            ) const

/**
 * Ends the declaration of an XMLObjectBuilder specialization.
 */
#define END_XMLOBJECTBUILDER }

/**
 * Declares a generic XMLObjectBuilder specialization.
 *
 * @param linkage           linkage specifier for the class
 * @param cname             the name of the XMLObject specialization
 * @param namespaceURI      the XML namespace of the default associated element
 * @param namespacePrefix   the XML namespace prefix of the default associated element
 */
 #define DECL_XMLOBJECTBUILDER(linkage,cname,namespaceURI,namespacePrefix) \
    BEGIN_XMLOBJECTBUILDER(linkage,cname,namespaceURI,namespacePrefix); \
    XMLTOOLING_DOXYGEN(Singleton builder.) \
    static cname* build##cname() { \
        const cname##Builder* b = dynamic_cast<const cname##Builder*>( \
            XMLObjectBuilder::getBuilder(xmltooling::QName(namespaceURI,cname::LOCAL_NAME)) \
            ); \
        if (b) \
            return dynamic_cast<cname*>(b->buildObject()); \
        throw xmltooling::XMLObjectException("Unable to obtain typed builder for "#cname"."); \
    } \
    END_XMLOBJECTBUILDER

/**
 * Implements the standard XMLObjectBuilder specialization function.
 *
 * @param cname the name of the XMLObject specialization
 */
#define IMPL_XMLOBJECTBUILDER(cname) \
    xmltooling::XMLObject* cname##Builder::buildObject( \
        const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const xmltooling::Name* schemaType \
        ) const \
    { \
        return new cname##Impl(nsURI,localName,prefix,schemaType); \
    }

#endif  /* HAVE_COVARIANT_RETURNS */

/**
 * Begins the declaration of a Schema Validator specialization.
 *
 * @param linkage           linkage specifier for the class
 * @param cname the base name of the Validator specialization
 */
 #define BEGIN_XMLOBJECTVALIDATOR(linkage,cname) \
    class linkage cname##SchemaValidator : public xmltooling::Validator \
    { \
    public: \
        virtual ~cname##SchemaValidator() {} \
        virtual void validate(const xmltooling::XMLObject* xmlObject) const { \
            const cname* ptr=dynamic_cast<const cname*>(xmlObject); \
            if (!ptr) \
                throw xmltooling::ValidationException(#cname"SchemaValidator: unsupported object type ($1).",xmltooling::params(1,typeid(xmlObject).name())); \
            if (ptr->nil() && (ptr->hasChildren() || ptr->getTextContent())) \
            	throw xmltooling::ValidationException("Object has nil property but with children or content.")

/**
 * Begins the declaration of a Schema Validator specialization subclass.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the base name of the Validator specialization
 * @param base      base class for the validator
 */
 #define BEGIN_XMLOBJECTVALIDATOR_SUB(linkage,cname,base) \
    class linkage cname##SchemaValidator : public base##SchemaValidator \
    { \
    public: \
        virtual ~cname##SchemaValidator() {} \
        virtual void validate(const xmltooling::XMLObject* xmlObject) const { \
            const cname* ptr=dynamic_cast<const cname*>(xmlObject); \
            if (!ptr) \
                throw xmltooling::ValidationException(#cname"SchemaValidator: unsupported object type ($1).",xmltooling::params(1,typeid(xmlObject).name()));

/**
 * Ends the declaration of a Validator specialization.
 */
#define END_XMLOBJECTVALIDATOR } }

/**
 * Validator code that checks the object type.
 *
 * @param cname     the name of the XMLObject specialization
 */
#define XMLOBJECTVALIDATOR_CHECKTYPE(cname) \
    const cname* ptr=dynamic_cast<const cname*>(xmlObject); \
    if (!ptr) \
        throw xmltooling::ValidationException(#cname"SchemaValidator: unsupported object type ($1).",xmltooling::params(1,typeid(xmlObject).name()))

/**
 * Validator code that checks for a required attribute, content, or singleton.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper    the proper name of the attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_REQUIRE(cname,proper) \
    if (!ptr->get##proper()) \
        throw xmltooling::ValidationException(#cname" must have "#proper".")

/**
 * Validator code that checks for a required integer attribute
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper    the proper name of the attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_REQUIRE_INTEGER(cname,proper) \
    if (!ptr->get##proper().first) \
        throw xmltooling::ValidationException(#cname" must have "#proper".")

/**
 * Validator code that checks for one of a pair of
 * required attributes, content, or singletons.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper1   the proper name of the first attribute, content, or singleton member
 * @param proper2   the proper name of the second attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_ONEOF(cname,proper1,proper2) \
    if (!ptr->get##proper1() && !ptr->get##proper2()) \
        throw xmltooling::ValidationException(#cname" must have "#proper1" or "#proper2".")

/**
 * Validator code that checks for one of a pair of
 * required attributes, content, or singletons, but disallows both.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper1   the proper name of the first attribute, content, or singleton member
 * @param proper2   the proper name of the second attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_ONLYONEOF(cname,proper1,proper2) \
    if ((!ptr->get##proper1() && !ptr->get##proper2()) || (ptr->get##proper1() && ptr->get##proper2())) \
        throw xmltooling::ValidationException(#cname" must have "#proper1" or "#proper2" but not both.")

/**
 * Validator code that checks for one of a set of three
 * required attributes, content, or singletons.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper1   the proper name of the first attribute, content, or singleton member
 * @param proper2   the proper name of the second attribute, content, or singleton member
 * @param proper3   the proper name of the third attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_ONEOF3(cname,proper1,proper2,proper3) \
    if (!ptr->get##proper1() && !ptr->get##proper2() && !ptr->get##proper3()) \
        throw xmltooling::ValidationException(#cname" must have "#proper1", "#proper2", or "#proper3".")

/**
 * Validator code that checks for one of a set of three
 * required attributes, content, or singletons but disallows more than one.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper1   the proper name of the first attribute, content, or singleton member
 * @param proper2   the proper name of the second attribute, content, or singleton member
 * @param proper3   the proper name of the third attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_ONLYONEOF3(cname,proper1,proper2,proper3) \
    int c##proper1##proper2##proper3=0; \
    if (ptr->get##proper1()!=NULL) \
        c##proper1##proper2##proper3++; \
    if (ptr->get##proper2()!=NULL) \
        c##proper1##proper2##proper3++; \
    if (ptr->get##proper3()!=NULL) \
        c##proper1##proper2##proper3++; \
    if (c##proper1##proper2##proper3 != 1) \
        throw xmltooling::ValidationException(#cname" must have only one of "#proper1", "#proper2", or "#proper3".")

/**
 * Validator code that checks a co-constraint (if one present, the other must be)
 * between a pair of attributes, content, or singletons.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper1   the proper name of the first attribute, content, or singleton member
 * @param proper2   the proper name of the second attribute, content, or singleton member
 */
#define XMLOBJECTVALIDATOR_NONEORBOTH(cname,proper1,proper2) \
    if ((ptr->get##proper1() && !ptr->get##proper2()) || (!ptr->get##proper1() && ptr->get##proper2())) \
        throw xmltooling::ValidationException(#cname" cannot have "#proper1" without "#proper2".")

/**
 * Validator code that checks for a non-empty collection.
 *
 * @param cname     the name of the XMLObject specialization
 * @param proper    the proper name of the collection item
 */
#define XMLOBJECTVALIDATOR_NONEMPTY(cname,proper) \
    if (ptr->get##proper##s().empty()) \
        throw xmltooling::ValidationException(#cname" must have at least one "#proper".")

/**
 * Declares/defines a Validator specialization that checks object type and
 * a non-empty simple content model.
 *
 * @param linkage   linkage specifier for the class
 * @param cname     the name of the XMLObject specialization
 */
#define XMLOBJECTVALIDATOR_SIMPLE(linkage,cname) \
    BEGIN_XMLOBJECTVALIDATOR(linkage,cname); \
        XMLOBJECTVALIDATOR_REQUIRE(cname,TextContent); \
    END_XMLOBJECTVALIDATOR

#include <utility>

/**
 * @namespace xmltooling
 * Public namespace of XML Tooling library
 */
namespace xmltooling {

    /**
     * Template function for cloning a sequence of XMLObjects.
     * Invokes the clone() member on each element of the input sequence and adds the copy to
     * the output sequence. Order is preserved.
     *
     * @param in    input sequence to clone
     * @param out   output sequence to copy cloned pointers into
     */
    template<class InputSequence,class OutputSequence> void clone(const InputSequence& in, OutputSequence& out) {
        for (typename InputSequence::const_iterator i=in.begin(); i!=in.end(); i++) {
            if (*i)
                out.push_back((*i)->clone());
            else
                out.push_back(*i);
        }
    }

    /**
     * Functor for cleaning up heap objects in containers.
     */
    template<class T> struct cleanup
    {
        /**
         * Function operator to delete an object.
         *
         * @param ptr   object to delete
         */
        void operator()(T* ptr) {delete ptr;}

        /**
         * Function operator to delete an object stored as const.
         *
         * @param ptr   object to delete after casting away const
         */
        void operator()(const T* ptr) {delete const_cast<T*>(ptr);}
    };

    /**
     * Functor for cleaning up heap objects in key/value containers.
     */
    template<class A,class B> struct cleanup_pair
    {
        /**
         * Function operator to delete an object.
         *
         * @param p   a pair in which the second component is the object to delete
         */
        void operator()(const std::pair<const A,B*>& p) {delete p.second;}
    };

    /**
     * Functor for cleaning up const heap objects in key/value containers.
     */
    template<class A,class B> struct cleanup_const_pair
    {
        /**
         * Function operator to delete an object stored as const
         *
         * @param p   a pair in which the second component is the const object to delete
         */
        void operator()(const std::pair<const A,const B*>& p) {delete const_cast<B*>(p.second);}
    };
};

#endif /* __xmltooling_base_h__ */
