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
* @file xmltooling/security/OpenSSLSecurityHelper.cpp
*
* A helper class for working with OpenSSL keys.
*/
#include "internal.h"
#include "logging.h"
#include "security/impl/OpenSSLSupport.h"

#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyEC.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include "security/OpenSSLSecurityHelper.h"

#if !defined(XMLTOOLING_NO_XMLSEC) && defined (XSEC_HAVE_OPENSSL)

using namespace xmltooling::logging;
using namespace xmltooling;

bool OpenSSLSecurityHelper::matchesPublic(const RSA* rsa, const XSECCryptoKey& key)
{
    // If one key is public or both, just compare the public key half.
    if (key.getKeyType() != XSECCryptoKey::KEY_RSA_PUBLIC && key.getKeyType() != XSECCryptoKey::KEY_RSA_PAIR)
        return false;

    const RSA* rsa1 = static_cast<const OpenSSLCryptoKeyRSA&>(key).getOpenSSLRSA();
    return (rsa1 && rsa && BN_cmp(xmltooling::RSA_get0_n(rsa1), xmltooling::RSA_get0_n(rsa)) == 0 && BN_cmp(xmltooling::RSA_get0_e(rsa1), xmltooling::RSA_get0_e(rsa)) == 0);
}
bool OpenSSLSecurityHelper::matchesPrivate(const RSA* rsa, const XSECCryptoKey& key)
{
    // For a private key, compare the private half.
    if (key.getKeyType() != XSECCryptoKey::KEY_RSA_PRIVATE && key.getKeyType() != XSECCryptoKey::KEY_RSA_PAIR)
        return false;

    const RSA* rsa2 = static_cast<const OpenSSLCryptoKeyRSA&>(key).getOpenSSLRSA();
    return (rsa && rsa2 && BN_cmp(xmltooling::RSA_get0_n(rsa), xmltooling::RSA_get0_n(rsa2)) == 0 && BN_cmp(xmltooling::RSA_get0_d(rsa), xmltooling::RSA_get0_d(rsa2)) == 0);
}
bool OpenSSLSecurityHelper::matchesPublic(const DSA* dsa, const XSECCryptoKey& key)
{
    // If one key is public or both, just compare the public key half.
    if (key.getKeyType() != XSECCryptoKey::KEY_DSA_PUBLIC && key.getKeyType() != XSECCryptoKey::KEY_DSA_PAIR)
        return false;

    const DSA* dsa2 = static_cast<const OpenSSLCryptoKeyDSA&>(key).getOpenSSLDSA();
    return (dsa && dsa2 && BN_cmp(DSA_get0_pubkey(dsa), DSA_get0_pubkey(dsa2)) == 0);
}
bool OpenSSLSecurityHelper::matchesPrivate(const DSA* dsa, const XSECCryptoKey& key)
{
    // For a private key, compare the private half.
    if (key.getKeyType() != XSECCryptoKey::KEY_DSA_PRIVATE && key.getKeyType() != XSECCryptoKey::KEY_DSA_PAIR)
        return false;

    const DSA* dsa2 = static_cast<const OpenSSLCryptoKeyDSA&>(key).getOpenSSLDSA();
    return (dsa && dsa2 && BN_cmp(DSA_get0_privkey(dsa), DSA_get0_privkey(dsa2)) == 0);
}
#ifdef XSEC_OPENSSL_HAVE_EC
bool OpenSSLSecurityHelper::matchesPublic(const EC_KEY* ec, const XSECCryptoKey& key)
{
    // If one key is public or both, just compare the public key half.
    if (key.getKeyType() != XSECCryptoKey::KEY_EC_PUBLIC && key.getKeyType() != XSECCryptoKey::KEY_EC_PAIR)
        return false;

    const EC_KEY* ec2 = static_cast<const OpenSSLCryptoKeyEC&>(key).getOpenSSLEC();
    if (!ec || !ec2)
        return false;

    if (EC_GROUP_cmp(EC_KEY_get0_group(ec), EC_KEY_get0_group(ec2), nullptr) != 0)
        return false;

    return (EC_POINT_cmp(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec), EC_KEY_get0_public_key(ec2), nullptr) == 0);
}
bool OpenSSLSecurityHelper::matchesPrivate(const EC_KEY* ec, const XSECCryptoKey& key)
{
    // For a private key, compare the private half.
    if (key.getKeyType() != XSECCryptoKey::KEY_EC_PRIVATE && key.getKeyType() != XSECCryptoKey::KEY_EC_PAIR)
        return false;

    const EC_KEY* ec2 = static_cast<const OpenSSLCryptoKeyEC&>(key).getOpenSSLEC();
    return (ec && ec2 && BN_cmp(EC_KEY_get0_private_key(ec), EC_KEY_get0_private_key(ec2)) == 0);
}
#endif
#endif
