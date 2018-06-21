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

#include "XMLObjectBaseTestCase.h"

#include <fstream>

#include <xmltooling/security/X509Credential.h>
#include <xmltooling/security/KeyInfoResolver.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/signature/KeyInfo.h>

#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
extern "C" {
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#include <openssl/x509_vfy.h>
#endif
}

#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyEC.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>

using namespace xmlsignature;

class InlineKeyResolverTest : public CxxTest::TestSuite {
    KeyInfoResolver* m_resolver;
public:
    InlineKeyResolverTest() : m_resolver(nullptr) {}

    void setUp() {
        string config = data_path + "InlineKeyResolver.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);
        m_resolver=XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(
            INLINE_KEYINFO_RESOLVER, doc->getDocumentElement(), false
            );
    }

    void tearDown() {
        delete m_resolver;
        m_resolver=nullptr;
    }

    void testResolver() {
        string path=data_path + "KeyInfo1.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getValidatingParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        scoped_ptr<X509Credential> cred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", cred.get()!=nullptr);

        TSM_ASSERT("Unable to resolve public key.", cred->getPublicKey()!=nullptr);
        TSM_ASSERT_EQUALS("Unexpected key type.", cred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);
        TSM_ASSERT_EQUALS("Wrong certificate count.", cred->getEntityCertificateChain().size(), 1);
        TSM_ASSERT_EQUALS("Wrong CRL count.", cred->getCRLs().size(), 3);
    }

    void testOpenSSLDSA() {

        string path=data_path + "KeyInfoDSA.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getValidatingParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        scoped_ptr<X509Credential> credFromKeyInfo(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        const OpenSSLCryptoKeyDSA* keyInfoDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(credFromKeyInfo->getPublicKey());

        path = data_path + "FilesystemCredentialResolver.xml";
        ifstream in(path.c_str());
        DOMDocument* cdoc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> cjanitor(cdoc);
        CredentialResolver* cresolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
            CHAINING_CREDENTIAL_RESOLVER, cdoc->getDocumentElement(), false
            );

        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("DSA");
        const OpenSSLCryptoKeyDSA* fileResolverDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(cresolver->resolve(&cc)->getPublicKey());

        unsigned char toSign[] = "Nibble A Happy WartHog";
        const int bufferSize = 1024;
        char outSig[bufferSize] = {0};

        unsigned int len = fileResolverDSA->signBase64Signature(toSign, 20, outSig, bufferSize);

        bool worked = fileResolverDSA->verifyBase64Signature(toSign, 20, outSig, len);
        TSM_ASSERT("Round trip file resolver DSA failed", worked);

        worked = keyInfoDSA->verifyBase64Signature(toSign, 20, outSig, len);
        TSM_ASSERT("Round trip KeyInfo DSA failed", worked);

    }

    void testOpenSSLEC() {
#ifdef XSEC_OPENSSL_HAVE_EC
        string path=data_path + "KeyInfoEC.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getValidatingParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        scoped_ptr<X509Credential> credFromKeyInfo(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        const OpenSSLCryptoKeyEC* sslCredFromKeyInfo= dynamic_cast<const OpenSSLCryptoKeyEC*>(credFromKeyInfo->getPublicKey());

        path = data_path + "FilesystemCredentialResolver.xml";
        ifstream in(path.c_str());
        DOMDocument* cdoc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> cjanitor(cdoc);
        CredentialResolver* cresolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
            CHAINING_CREDENTIAL_RESOLVER, cdoc->getDocumentElement(), false
            );

        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("EC");
        const OpenSSLCryptoKeyEC* fileResolverCryptoKeyEC = dynamic_cast<const OpenSSLCryptoKeyEC*>(cresolver->resolve(&cc)->getPublicKey());

        unsigned char toSign[] = "NibbleAHappyWartHog";
        const int bufferSize = 1024;
        char outSig[bufferSize] = {0};
        unsigned int len = fileResolverCryptoKeyEC->signBase64SignatureDSA(toSign, sizeof(toSign), &outSig[0], bufferSize);

        bool worked = sslCredFromKeyInfo->verifyBase64SignatureDSA(toSign, sizeof(toSign), &outSig[0], len);
        TSM_ASSERT("EC Round Trip Signature via KeyInfo Failed", worked);
#endif
    }

    void testOpenSSLRSA() {
        string path=data_path + "KeyInfo1.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getValidatingParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        scoped_ptr<X509Credential> cred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        scoped_ptr<X509Credential> key(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get(), Credential::RESOLVE_KEYS)));

        const OpenSSLCryptoKeyRSA* sslCred = dynamic_cast<const OpenSSLCryptoKeyRSA*>(cred->getPublicKey());
        const OpenSSLCryptoKeyRSA* sslKey = dynamic_cast<const OpenSSLCryptoKeyRSA*>(key->getPublicKey());

        const RSA* rsaCred = sslCred->getOpenSSLRSA();
        const RSA* rsaKey = sslKey->getOpenSSLRSA();

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        BIGNUM* n = rsaCred->n;
        BIGNUM* e = rsaCred->e;
        BIGNUM* d = rsaCred->d;
        BIGNUM* p = rsaCred->p;
        BIGNUM* q = rsaCred->q;
        BIGNUM* dmp1 = rsaCred->dmp1;
        BIGNUM* dmq1 = rsaCred->dmq1;
        BIGNUM* iqmp = rsaCred->iqmp;

        BIGNUM* kn = rsaKey->n;
        BIGNUM* ke = rsaKey->e;
        BIGNUM* kd = rsaKey->d;
        BIGNUM* kp = rsaKey->p;
        BIGNUM* kq = rsaKey->q;
        BIGNUM* kdmp1 = rsaKey->dmp1;
        BIGNUM* kdmq1 = rsaKey->dmq1;
        BIGNUM* kiqmp = rsaKey->iqmp;
#else
        const BIGNUM *n, *e, *d; RSA_get0_key(rsaCred, &n, &e, &d);
        const BIGNUM *p, *q;  RSA_get0_factors(rsaCred, &p, &q);
        const BIGNUM *dmp1, *dmq1, *iqmp; RSA_get0_crt_params(rsaCred, &dmp1, &dmq1, &iqmp);

        const BIGNUM *kn, *ke, *kd; RSA_get0_key(rsaKey, &kn, &ke, &kd);
        const BIGNUM *kp, *kq;  RSA_get0_factors(rsaKey, &kp, &kq);
        const BIGNUM *kdmp1, *kdmq1, *kiqmp; RSA_get0_crt_params(rsaKey, &kdmp1, &kdmq1, &kiqmp);
#endif
        TS_ASSERT(0 == BN_cmp(kn, n));
        TS_ASSERT(0 == BN_cmp(ke, e));
        TS_ASSERT(0 ==  BN_cmp(kd, d));
        TS_ASSERT(0 ==  BN_cmp(kp, p));
        TS_ASSERT(0 == BN_cmp(kq, q));
        TS_ASSERT(0 ==  BN_cmp(kdmp1, dmp1));
        TS_ASSERT(0 ==  BN_cmp(kdmq1, dmq1));
        TS_ASSERT(0 ==  BN_cmp(kiqmp, iqmp));
    }


    void testDER() {
        string path=data_path + "KeyInfo5.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getValidatingParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        scoped_ptr<X509Credential> cred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", cred.get()!=nullptr);

        TSM_ASSERT("Unable to resolve public key.", cred->getPublicKey()!=nullptr);
        TSM_ASSERT_EQUALS("Unexpected key type.", cred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);
        TSM_ASSERT_EQUALS("Wrong certificate count.", cred->getEntityCertificateChain().size(), 0);
        TSM_ASSERT_EQUALS("Wrong CRL count.", cred->getCRLs().size(), 0);
    }
};
