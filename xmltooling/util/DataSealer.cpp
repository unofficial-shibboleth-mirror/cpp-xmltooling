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
 * URLEncoder.cpp
 * 
 * Interface to a URL-encoding mechanism along with a
 * default implementation. 
 */

#include "internal.h"
#include "logging.h"
#include "util/DataSealer.h"
#include "util/XMLHelper.h"

#include <sstream>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLDateTime.hpp>

using namespace xmltooling;
using xercesc::Base64;
using xercesc::XMLDateTime;
using namespace std;

DataSealer::DataSealer()
{
}

DataSealer::~DataSealer()
{
}

// TODO: add encryption ;-)

string DataSealer::wrap(const char* s, time_t exp) const
{
#ifndef HAVE_GMTIME_R
    struct tm* ptime = gmtime(&exp);
#else
    struct tm res;
    struct tm* ptime = gmtime_r(exp, &res);
#endif
    char timebuf[32];
    strftime(timebuf, 32, "%Y-%m-%dT%H:%M:%SZ", ptime);

    string towrap(timebuf);
    towrap += s;

    unsigned int len;
    char* deflated = XMLHelper::deflate(const_cast<char*>(towrap.c_str()), towrap.length(), &len);
    if (!deflated)
        throw IOException("Failed to deflate data.");

    XMLSize_t xlen;
    XMLByte* encoded = Base64::encode(reinterpret_cast<XMLByte*>(deflated), len, &xlen);
    delete[] deflated;
    if (!encoded)
        throw IOException("Base64 encoding of deflated data failed.");

    string wrapped;
    for (const XMLByte* xb = encoded; *xb; ++xb) {
        if (!isspace(*xb))
            wrapped += *xb;
    }
    XMLString::release((char**)&encoded);

    return wrapped;
}

string DataSealer::decode(const char* wrapped) const
{
    XMLSize_t x;
    XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(wrapped), &x);
    if (!decoded)
        throw IOException("Unable to decode base64 data.");

    // Now we have to inflate it.
    stringstream s;
    if (XMLHelper::inflate(reinterpret_cast<char*>(decoded), x, s) == 0) {
        XMLString::release((char**)&decoded);
        throw IOException("Unable to inflate wrapped data.");
    }
    XMLString::release((char**)&decoded);

    string decrypted = s.str();
    string dstr = decrypted.substr(0, 20);
    auto_ptr_XMLCh expstr(dstr.c_str());
    XMLDateTime exp(expstr.get());
    exp.parseDateTime();
    if (exp.getEpoch() < time(nullptr) - XMLToolingConfig::getConfig().clock_skew_secs) {
        logging::Category::getInstance(XMLTOOLING_LOGCAT ".DataSealer").debug("Decrypted data has expired");
    }

    return decrypted.substr(20);
}
