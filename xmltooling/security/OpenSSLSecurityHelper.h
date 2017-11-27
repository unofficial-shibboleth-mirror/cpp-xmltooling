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
 * @file xmltooling/security/OpenSSLSecurityHelper.h
 *
 * A helper class for working with OpenSSL keys.
 */

#if !defined(__xmltooling_opensslsechelper_h__) && !defined(XMLTOOLING_NO_XMLSEC) && defined (XSEC_HAVE_OPENSSL)
#define __xmltooling_opensslsechelper_h__

#include <xmltooling/base.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

namespace xmltooling {
    /**
     * A helper class for working with OpenSSL keys.
     */
    class XMLTOOL_API OpenSSLSecurityHelper
    {
    public:
        /**
         * Compares two keys for equality.
         *
         * @param key1 first key to compare
         * @param key2 second key to compare
         * @return  true iff the keys match
         */
        static bool matchesPublic(const RSA* rsa, const XSECCryptoKey& key);
        static bool matchesPrivate(const RSA* rsa, const XSECCryptoKey& key);
        static bool matchesPublic(const DSA* dsa1, const XSECCryptoKey& key);
        static bool matchesPrivate(const DSA* dsa, const XSECCryptoKey& key);
#ifdef XSEC_OPENSSL_HAVE_EC
        static bool matchesPublic(const EC_KEY* ec, const XSECCryptoKey& key);
        static bool matchesPrivate(const EC_KEY* ec, const XSECCryptoKey& key);
#endif
    };
};

#endif /* __xmltooling_sechelper_h__ */
