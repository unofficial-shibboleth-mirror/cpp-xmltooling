/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * HTTPResponse.cpp
 * 
 * Interface to HTTP responses.
 */

#include "internal.h"
#include "HTTPResponse.h"

#include <boost/algorithm/string/predicate.hpp>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/bind.hpp>

using namespace xmltooling;
using namespace boost;
using namespace std;

GenericResponse::GenericResponse()
{
}

GenericResponse::~GenericResponse()
{
}

vector<string> HTTPResponse::m_allowedSchemes;

vector<string>& HTTPResponse::getAllowedSchemes()
{
    return m_allowedSchemes;
}

void HTTPResponse::sanitizeURL(const char* url)
{
    // predicate for checking scheme below
    static bool (*fn)(const string&, const string&, const std::locale&) = iequals;

    const char* ch;
    for (ch=url; *ch; ++ch) {
        if (iscntrl((unsigned char)(*ch)))  // convert to unsigned to allow full range from 00-FF
            throw IOException("URL contained a control character.");
    }

    ch = strchr(url, ':');
    if (!ch)
        throw IOException("URL is missing a colon where expected; improper URL encoding?");
    string s(url, ch - url);
    std::locale loc;
    vector<string>::const_iterator i =
        find_if(m_allowedSchemes.begin(), m_allowedSchemes.end(), boost::bind(fn, boost::cref(s), _1, boost::cref(loc)));
    if (i != m_allowedSchemes.end())
        return;

    throw IOException("URL contains invalid scheme ($1).", params(1, s.c_str()));
}

HTTPResponse::HTTPResponse()
{
}

HTTPResponse::~HTTPResponse()
{
}

void HTTPResponse::setContentType(const char* type)
{
    setResponseHeader("Content-Type", type);
}

void HTTPResponse::setCookie(const char* name, const char* value, time_t expires, samesite_t sameSiteValue)
{
    setCookie(name, value, expires, sameSiteValue, false);
}

void HTTPResponse::setCookie(const char* name, const char* value, time_t expires, samesite_t sameSiteValue, bool sameSiteFallback)
{
    string decoratedValue;
    if (!value) {
        decoratedValue += "; expires=Mon, 01 Jan 2001 00:00:00 GMT";
    }
    else {
        decoratedValue = value;
        if (expires > 0) {
            expires += time(nullptr);
#ifndef HAVE_GMTIME_R
            struct tm* ptime = gmtime(&expires);
#else
            struct tm res;
            struct tm* ptime = gmtime_r(&expires, &res);
#endif
            char cookietimebuf[64];
            strftime(cookietimebuf, 64, "; expires=%a, %d %b %Y %H:%M:%S GMT", ptime);
            decoratedValue.append(cookietimebuf);
        }
    }

    if (sameSiteValue != SAMESITE_ABSENT) {
        // Add SameSite to the primary cookie and optionally set a fallback cookie without SameSite.
        switch (sameSiteValue) {
            case SAMESITE_NONE:
                if (sameSiteFallback) {
                    string hackedName(name);
                    setResponseHeader("Set-Cookie", hackedName.append("_fgwars=").append(decoratedValue).c_str());
                }
                decoratedValue.append("; SameSite=None");
                break;
            case SAMESITE_LAX:
                decoratedValue.append("; SameSite=Lax");
                break;
            case SAMESITE_STRICT:
                decoratedValue.append("; SameSite=Strict");
                break;
            default:
                throw IOException("Invalid SameSite value supplied");
        }
        string header(name);
        setResponseHeader("Set-Cookie", header.append("=").append(decoratedValue).c_str());
    }
    else {
        string header(name);
        setResponseHeader("Set-Cookie", header.append("=").append(decoratedValue).c_str());
    }
}

void HTTPResponse::setResponseHeader(const char* name, const char* value, bool replace)
{
    if (name) {
        for (const char* ch=name; *ch; ++ch) {
            if (iscntrl(*ch))
                throw IOException("Response header name contained a control character.");
        }
    }

    if (value) {
        for (const char* ch=value; *ch; ++ch) {
            if (iscntrl(*ch))
                throw IOException("Value for response header ($1) contained a control character.", params(1,name));
        }
    }
}

long HTTPResponse::sendRedirect(const char* url)
{
    sanitizeURL(url);
    return XMLTOOLING_HTTP_STATUS_MOVED;
}

long HTTPResponse::sendError(istream& inputStream)
{
    return sendResponse(inputStream, XMLTOOLING_HTTP_STATUS_ERROR);
}

long HTTPResponse::sendResponse(istream& inputStream)
{
    return sendResponse(inputStream, XMLTOOLING_HTTP_STATUS_OK);
}
