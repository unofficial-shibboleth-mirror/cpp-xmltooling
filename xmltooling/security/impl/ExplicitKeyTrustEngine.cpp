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
 * ExplicitKeyTrustEngine.cpp
 * 
 * TrustEngine based on explicit knowledge of peer key information.
 */

#include "internal.h"
#include "logging.h"
#include "security/Credential.h"
#include "security/CredentialCriteria.h"
#include "security/CredentialResolver.h"
#include "security/OpenSSLTrustEngine.h"
#include "security/SignatureTrustEngine.h"
#include "signature/Signature.h"
#include "signature/SignatureValidator.h"
#include "util/NDC.h"
#include "security/impl/OpenSSLSupport.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

#include "security/OpenSSLSecurityHelper.h"
#ifdef XSEC_OPENSSL_HAVE_EC
# include <openssl/ec.h>
#endif

using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;


using xercesc::DOMElement;

namespace xmltooling {
    class XMLTOOL_DLLLOCAL ExplicitKeyTrustEngine : public SignatureTrustEngine, public OpenSSLTrustEngine
    {
    public:
        ExplicitKeyTrustEngine(const DOMElement* e) : TrustEngine(e) {}
        virtual ~ExplicitKeyTrustEngine() {}

        virtual bool validate(
            Signature& sig,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=nullptr
            ) const;
        virtual bool validate(
            const XMLCh* sigAlgorithm,
            const char* sig,
            KeyInfo* keyInfo,
            const char* in,
            unsigned int in_len,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=nullptr
            ) const;
        virtual bool validate(
            XSECCryptoX509* certEE,
            const vector<XSECCryptoX509*>& certChain,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=nullptr
            ) const;
        virtual bool validate(
            X509* certEE,
            STACK_OF(X509)* certChain,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=nullptr
            ) const;
    };

    TrustEngine* XMLTOOL_DLLLOCAL ExplicitKeyTrustEngineFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new ExplicitKeyTrustEngine(e);
    }
};

bool ExplicitKeyTrustEngine::validate(
    Signature& sig,
    const CredentialResolver& credResolver,
    CredentialCriteria* criteria
    ) const
{
#ifdef _DEBUG
    NDC ndc("validate");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT ".TrustEngine." EXPLICIT_KEY_TRUSTENGINE);

    vector<const Credential*> credentials;
    if (criteria) {
        criteria->setUsage(Credential::SIGNING_CREDENTIAL);
        criteria->setSignature(sig, CredentialCriteria::KEYINFO_EXTRACTION_KEY);
        credResolver.resolve(credentials,criteria);
    }
    else {
        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setSignature(sig, CredentialCriteria::KEYINFO_EXTRACTION_KEY);
        credResolver.resolve(credentials,&cc);
    }
    if (credentials.empty()) {
        log.debug("unable to validate signature, no credentials available from peer");
        return false;
    }
    
    log.debug("attempting to validate signature with the peer's credentials");
    SignatureValidator sigValidator;
    for (vector<const Credential*>::const_iterator c=credentials.begin(); c!=credentials.end(); ++c) {
        sigValidator.setCredential(*c);
        try {
            sigValidator.validate(&sig);
            log.debug("signature validated with credential");
            return true;
        }
        catch (ValidationException& e) {
            log.debug("public key did not validate signature: %s", e.what());
        }
    }

    log.debug("no peer credentials validated the signature");
    return false;
}

bool ExplicitKeyTrustEngine::validate(
    const XMLCh* sigAlgorithm,
    const char* sig,
    KeyInfo* keyInfo,
    const char* in,
    unsigned int in_len,
    const CredentialResolver& credResolver,
    CredentialCriteria* criteria
    ) const
{
#ifdef _DEBUG
    NDC ndc("validate");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT ".TrustEngine." EXPLICIT_KEY_TRUSTENGINE);
    
    vector<const Credential*> credentials;
    if (criteria) {
        criteria->setUsage(Credential::SIGNING_CREDENTIAL);
        criteria->setKeyInfo(keyInfo, CredentialCriteria::KEYINFO_EXTRACTION_KEY);
        criteria->setXMLAlgorithm(sigAlgorithm);
        credResolver.resolve(credentials,criteria);
    }
    else {
        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyInfo(keyInfo, CredentialCriteria::KEYINFO_EXTRACTION_KEY);
        cc.setXMLAlgorithm(sigAlgorithm);
        credResolver.resolve(credentials,&cc);
    }
    if (credentials.empty()) {
        log.debug("unable to validate signature, no credentials available from peer");
        return false;
    }
    
    log.debug("attempting to validate signature with the peer's credentials");
    for (vector<const Credential*>::const_iterator c=credentials.begin(); c!=credentials.end(); ++c) {
        if ((*c)->getPublicKey()) {
            try {
                if (Signature::verifyRawSignature((*c)->getPublicKey(), sigAlgorithm, sig, in, in_len)) {
                    log.debug("signature validated with public key");
                    return true;
                }
            }
            catch (SignatureException& e) {
                if (log.isDebugEnabled()) {
                    log.debug("public key did not validate signature: %s", e.what());
                }
            }
        }
    }

    log.debug("no peer credentials validated the signature");
    return false;
}

bool ExplicitKeyTrustEngine::validate(
    XSECCryptoX509* certEE,
    const vector<XSECCryptoX509*>& certChain,
    const CredentialResolver& credResolver,
    CredentialCriteria* criteria
    ) const
{
#ifdef _DEBUG
        NDC ndc("validate");
#endif
    if (!certEE) {
        Category::getInstance(XMLTOOLING_LOGCAT ".TrustEngine." EXPLICIT_KEY_TRUSTENGINE).error("unable to validate, end-entity certificate was null");
        return false;
    }
    else if (certEE->getProviderName()!=DSIGConstants::s_unicodeStrPROVOpenSSL) {
        Category::getInstance(XMLTOOLING_LOGCAT ".TrustEngine." EXPLICIT_KEY_TRUSTENGINE).error("only the OpenSSL XSEC provider is supported");
        return false;
    }

    return validate(static_cast<OpenSSLCryptoX509*>(certEE)->getOpenSSLX509(), nullptr, credResolver, criteria);
}

bool ExplicitKeyTrustEngine::validate(
    X509* certEE,
    STACK_OF(X509)* certChain,
    const CredentialResolver& credResolver,
    CredentialCriteria* criteria
    ) const
{
#ifdef _DEBUG
    NDC ndc("validate");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT ".TrustEngine." EXPLICIT_KEY_TRUSTENGINE);
    
    if (!certEE) {
        log.error("unable to validate, end-entity certificate was null");
        return false;
    }

    vector<const Credential*> credentials;
    if (criteria) {
        if (criteria->getUsage()==Credential::UNSPECIFIED_CREDENTIAL)
            criteria->setUsage(Credential::SIGNING_CREDENTIAL);
        credResolver.resolve(credentials,criteria);
    }
    else {
        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        credResolver.resolve(credentials,&cc);
    }
    if (credentials.empty()) {
        log.debug("unable to validate certificate, no credentials available from peer");
        return false;
    }

    // The "explicit" trust implementation relies solely on keys living within the
    // peer resolver to verify the EE certificate.

    log.debug("attempting to match credentials from peer with end-entity certificate");
    bool found = false;
    EVP_PKEY* evp = X509_PUBKEY_get(X509_get_X509_PUBKEY(certEE));
    if (!evp)
        return false;

    for (vector<const Credential*>::const_iterator c=credentials.begin(); c != credentials.end(); ++c) {
        const XSECCryptoKey* key = (*c)->getPublicKey();
        if (!key)
            continue;
        if (key->getProviderName() != DSIGConstants::s_unicodeStrPROVOpenSSL) {
            log.error("only the OpenSSL XSEC provider is supported");
            continue;
        }

        if (EVP_PKEY_id(evp) == EVP_PKEY_RSA) {
            found = OpenSSLSecurityHelper::matchesPublic(EVP_PKEY_get0_RSA(evp), *key);
            if (found) {
                log.debug("end-entity certificate matches peer RSA key information");
                break;
            }
        }
        else if (EVP_PKEY_id(evp) == EVP_PKEY_DSA) {
            found = OpenSSLSecurityHelper::matchesPublic(EVP_PKEY_get0_DSA(evp), *key);
            if (found) {
                log.debug("end-entity certificate matches peer RSA key information");
                break;
            }
        }
#ifdef XSEC_OPENSSL_HAVE_EC
        else if (EVP_PKEY_id(evp) == EVP_PKEY_EC) {
            found = OpenSSLSecurityHelper::matchesPublic(EVP_PKEY_get0_EC_KEY(evp), *key);
            if (found) {
                log.debug("end-entity certificate matches peer EC key information");
                break;
            }
        }
#endif
        else {
            log.warn("unknown peer key type, skipping...");
        }
    }
    EVP_PKEY_free(evp);
    if (!found)
        log.debug("no keys within this peer's key information matched the given end-entity certificate");
    return found;
}
