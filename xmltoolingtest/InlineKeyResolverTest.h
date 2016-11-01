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
#include <xmltooling/signature/KeyInfo.h>

#include <xsec/enc/XSECCryptoKey.hpp>

#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
extern "C" {
#include <openssl/opensslv.h>
}

// Force XMLSEC to assume OpenSSL
#define XSEC_HAVE_OPENSSL 1

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
        m_resolver=XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(INLINE_KEYINFO_RESOLVER,doc->getDocumentElement());
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
        auto_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        auto_ptr<X509Credential> cred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", cred.get()!=nullptr);

        TSM_ASSERT("Unable to resolve public key.", cred->getPublicKey()!=nullptr);
        TSM_ASSERT_EQUALS("Unexpected key type.", cred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);
        TSM_ASSERT_EQUALS("Wrong certificate count.", cred->getEntityCertificateChain().size(), 1);
        TSM_ASSERT_EQUALS("Wrong CRL count.", cred->getCRLs().size(), 3);
    }


    void testOpenSSLRSA() {
        string path=data_path + "KeyInfo1.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getValidatingParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        auto_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        auto_ptr<X509Credential> cred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        auto_ptr<X509Credential> key(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get(), Credential::RESOLVE_KEYS)));

        OpenSSLCryptoKeyRSA* sslCred = dynamic_cast<OpenSSLCryptoKeyRSA*>(cred->getPublicKey());
        OpenSSLCryptoKeyRSA* sslKey = dynamic_cast<OpenSSLCryptoKeyRSA*>(key->getPublicKey());

        RSA* rsaCred = sslCred->getOpenSSLRSA();
        RSA* rsaKey = sslKey->getOpenSSLRSA();

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
        auto_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        auto_ptr<X509Credential> cred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", cred.get()!=nullptr);

        TSM_ASSERT("Unable to resolve public key.", cred->getPublicKey()!=nullptr);
        TSM_ASSERT_EQUALS("Unexpected key type.", cred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);
        TSM_ASSERT_EQUALS("Wrong certificate count.", cred->getEntityCertificateChain().size(), 0);
        TSM_ASSERT_EQUALS("Wrong CRL count.", cred->getCRLs().size(), 0);
    }
};
