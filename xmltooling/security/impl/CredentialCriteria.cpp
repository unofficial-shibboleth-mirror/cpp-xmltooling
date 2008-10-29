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
 * CredentialCriteria.cpp
 *
 * Class for specifying criteria by which a CredentialResolver should resolve credentials.
 */

#include "internal.h"
#include "logging.h"
#include "security/Credential.h"
#include "security/CredentialCriteria.h"
#include "security/KeyInfoResolver.h"
#include "security/SecurityHelper.h"

#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>

using namespace xmltooling;
using namespace std;

bool CredentialCriteria::matches(const Credential& credential) const
{
    // Usage check, if specified and we have one, compare masks.
    if (getUsage() != Credential::UNSPECIFIED_CREDENTIAL) {
        if (credential.getUsage() != Credential::UNSPECIFIED_CREDENTIAL)
            if ((getUsage() & credential.getUsage()) == 0)
                return false;
    }

    // Algorithm check, if specified and we have one.
    const char* alg = getKeyAlgorithm();
    if (alg && *alg) {
        const char* alg2 = credential.getAlgorithm();
        if (alg2 && *alg2)
            if (strcmp(alg,alg2))
                return false;
    }

    // KeySize check, if specified and we have one.
    if (credential.getKeySize()>0 && getKeySize()>0 && credential.getKeySize() != getKeySize())
        return false;

    // See if we can test key names.
    const set<string>& critnames = getKeyNames();
    const set<string>& crednames = credential.getKeyNames();
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
    const XSECCryptoKey* key1 = getPublicKey();
    if (!key1)
        return true;    // no key to compare against, so we're done

    const XSECCryptoKey* key2 = credential.getPublicKey();
    if (!key2)
        return true;   // no key here, so we can't test it

    return SecurityHelper::matches(key1, key2);
}
