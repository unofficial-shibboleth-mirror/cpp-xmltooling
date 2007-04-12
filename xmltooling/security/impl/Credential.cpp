/*
 *  Copyright 2001-2007 Internet2
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
 * Credential.cpp
 * 
 * Wraps keys and related functionality. 
 */

#include "internal.h"
#include "security/Credential.h"
#include "security/CredentialCriteria.h"
#include "security/KeyInfoResolver.h"

#include <log4cpp/Category.hh>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>

using namespace xmltooling;
using namespace std;

bool Credential::matches(const CredentialCriteria& criteria) const
{
    // Algorithm check, if specified and we have one.
    const char* alg = criteria.getKeyAlgorithm();
    if (alg && *alg) {
        const char* alg2 = getAlgorithm();
        if (alg2 && *alg2)
            if (strcmp(alg,alg2))
                return false;
    }

    // KeySize check, if specified and we have one.
    if (criteria.getKeySize()>0 && getKeySize()>0 && criteria.getKeySize() != getKeySize())
        return false;

    // See if we can test key names.
    const set<string>& critnames = criteria.getKeyNames();
    const set<string>& crednames = getKeyNames();
    if (!critnames.empty() && !crednames.empty()) {
        bool found = false;
        for (set<string>::const_iterator n = critnames.begin(); n!=critnames.end(); ++n) {
            if (crednames.count(*n)>0) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }

    // See if we have to match a specific key.
    XSECCryptoKey* key1 = criteria.getPublicKey();
    if (!key1)
        return true;    // no key to compare against, so we're done

    XSECCryptoKey* key2 = getPublicKey();
    if (!key2)
        return false;   // no key here, so we can't possibly match the criteria

    if (key1->getProviderName()!=DSIGConstants::s_unicodeStrPROVOpenSSL ||
        key2->getProviderName()!=DSIGConstants::s_unicodeStrPROVOpenSSL) {
        log4cpp::Category::getInstance(XMLTOOLING_LOGCAT".Credential").warn("comparison of non-OpenSSL credentials are not supported");
        return false;
    }

    if (key1->getKeyType()==XSECCryptoKey::KEY_RSA_PUBLIC || key1->getKeyType()==XSECCryptoKey::KEY_RSA_PAIR) {
        if (key2->getKeyType()!=XSECCryptoKey::KEY_RSA_PUBLIC && key2->getKeyType()!=XSECCryptoKey::KEY_RSA_PAIR)
            return false;
        RSA* rsa1 = static_cast<OpenSSLCryptoKeyRSA*>(key1)->getOpenSSLRSA();
        RSA* rsa2 = static_cast<OpenSSLCryptoKeyRSA*>(key2)->getOpenSSLRSA();
        return (BN_cmp(rsa1->n,rsa2->n) == 0 && BN_cmp(rsa1->e,rsa2->e) == 0);
    }

    if (key1->getKeyType()==XSECCryptoKey::KEY_DSA_PUBLIC || key1->getKeyType()==XSECCryptoKey::KEY_DSA_PAIR) {
        if (key2->getKeyType()!=XSECCryptoKey::KEY_DSA_PUBLIC && key2->getKeyType()!=XSECCryptoKey::KEY_DSA_PAIR)
            return false;
        DSA* dsa1 = static_cast<OpenSSLCryptoKeyDSA*>(key1)->getOpenSSLDSA();
        DSA* dsa2 = static_cast<OpenSSLCryptoKeyDSA*>(key2)->getOpenSSLDSA();
        return (BN_cmp(dsa1->pub_key,dsa2->pub_key) == 0);
    }
    
    log4cpp::Category::getInstance(XMLTOOLING_LOGCAT".Credential").warn("unsupported key type for comparison");
    return false;
}
