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

#include <xmltooling/security/KeyInfoResolver.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/X509Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/encryption/Decrypter.h>
#include <xmltooling/encryption/Encrypter.h>
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/signature/KeyInfo.h>

#include <xsec/framework/XSECException.hpp>
#include <xsec/framework/XSECEnv.hpp>
#include <xsec/dsig/DSIGKeyInfoList.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xsec/enc/XSECCryptoKeyRSA.hpp>
#include <xsec/enc/XSECCryptoKey.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
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
using namespace xmlencryption;


class BadKeyInfoTest : public CxxTest::TestSuite {
private:
#define SIGBUFFER_SIZE 1024
    KeyInfoResolver* m_resolver;
    unsigned char m_toSign[23] = "Nibble A Happy WartHog";
    char m_outSigDSA[SIGBUFFER_SIZE] = { 0 };
    char m_outSigEC[SIGBUFFER_SIZE] = { 0 };
    unsigned int m_sigLenDSA;
    unsigned int m_sigLenEC;

public:
    BadKeyInfoTest() : m_resolver(nullptr), m_sigLenDSA(0), m_sigLenEC(0) {}

    void setUp() {
        string config = data_path + "InlineKeyResolver.xml";
        ifstream in(config.c_str());
        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);
        m_resolver = XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(
            INLINE_KEYINFO_RESOLVER, doc->getDocumentElement(), false
        );

        if (m_sigLenEC == 0 || m_sigLenDSA == 0) {
            // Resolver for DSA and RSA signatures
            config = data_path + "FilesystemCredentialResolver.xml";
            ifstream infc(config.c_str());
            DOMDocument* cdoc = XMLToolingConfig::getConfig().getParser().parse(infc);
            XercesJanitor<DOMDocument> cjanitor(cdoc);
            const CredentialResolver* cresolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
                CHAINING_CREDENTIAL_RESOLVER, cdoc->getDocumentElement(), false
            );

            if (m_sigLenDSA == 0) {
                // Test sign for DSA
                CredentialCriteria cc;
                cc.setUsage(Credential::SIGNING_CREDENTIAL);
                cc.setKeyAlgorithm("DSA");
                const OpenSSLCryptoKeyDSA* fileResolverDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(cresolver->resolve(&cc)->getPublicKey());
                m_sigLenDSA = fileResolverDSA->signBase64Signature(m_toSign, 20, m_outSigDSA, SIGBUFFER_SIZE);
                bool worked = fileResolverDSA->verifyBase64Signature(m_toSign, 20, m_outSigDSA, m_sigLenDSA);
                TSM_ASSERT("Round trip file resolver DSA failed", worked);
            }

            if (m_sigLenEC == 0) {
#ifdef XSEC_OPENSSL_HAVE_EC
                // Test sign for EC
                CredentialCriteria cc;
                cc.setUsage(Credential::SIGNING_CREDENTIAL);
                cc.setKeyAlgorithm("EC");
                const OpenSSLCryptoKeyEC* fileResolverCryptoKeyEC = dynamic_cast<const OpenSSLCryptoKeyEC*>(cresolver->resolve(&cc)->getPublicKey());
                m_sigLenEC = fileResolverCryptoKeyEC->signBase64SignatureDSA(m_toSign, 20, m_outSigEC, SIGBUFFER_SIZE);

                bool worked = fileResolverCryptoKeyEC->verifyBase64SignatureDSA(m_toSign, 20, m_outSigEC, m_sigLenEC);
                TSM_ASSERT("EC Round Trip SignatureFailed", worked);
#else
                m_m_sigLenEC = 1;
#endif
            }
        }

    }

    void tearDown() {
        delete m_resolver;
        m_resolver = nullptr;
    }

private:
    void RSATest(const char* file, bool encryptionThrows, bool nullKeys) {

        string path = data_path + file;
        ifstream fs(path.c_str());
        ParserPool& parser = XMLToolingConfig::getConfig().getParser();
        DOMDocument* doc = parser.parse(fs);

        TS_ASSERT(doc != nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b != nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get() != nullptr);

        const scoped_ptr<Credential> toolingCred(dynamic_cast<Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", toolingCred.get() != nullptr);
        TSM_ASSERT("Expected null Private Key", toolingCred->getPrivateKey() == nullptr);
        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));
        const scoped_ptr<DSIGKeyInfoList> xencKey(new DSIGKeyInfoList(env.get()));
        if (nullKeys) {
            TSM_ASSERT_EQUALS("Expected null Public Key", toolingCred->getPublicKey(), nullptr);
            TSM_ASSERT_THROWS("Lack of data should make xsec throw", xencKey->loadListFromXML(doc->getDocumentElement()), XSECException);
            return;
        }
        xencKey->loadListFromXML(doc->getDocumentElement());

        const scoped_ptr<Credential> xsecCred(dynamic_cast<Credential*>(m_resolver->resolve(xencKey.get())));
        TSM_ASSERT("Unable to resolve DSIGKeyInfoList into Credential.", xsecCred.get() != nullptr);
        TSM_ASSERT("Expected null Private Key", xsecCred->getPrivateKey() == nullptr);


        TSM_ASSERT("Expected non-null Public Key", toolingCred->getPublicKey() != nullptr);
        TSM_ASSERT_EQUALS("Expected RSA key", toolingCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);

        TSM_ASSERT("Expected non-null Public Key", xsecCred->getPublicKey() != nullptr);
        TSM_ASSERT_EQUALS("Expected RSA key", xsecCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);

        Encrypter encrypter;
        Encrypter::EncryptionParams ep;
        Encrypter::KeyEncryptionParams xsecKep(*xsecCred.get());
        Encrypter::KeyEncryptionParams toolingKep(*toolingCred.get());
        //
        if (encryptionThrows) {
            TSM_ASSERT_THROWS("Bad RSA key throws an assert", encrypter.encryptElement(doc->getDocumentElement(), ep, &xsecKep), EncryptionException);
            TSM_ASSERT_THROWS("Bad RSA key throws an assert", encrypter.encryptElement(doc->getDocumentElement(), ep, &toolingKep), EncryptionException);
        }
        else {
            scoped_ptr<EncryptedData> toolingEncData(encrypter.encryptElement(doc->getDocumentElement(), ep, &toolingKep));
            scoped_ptr<EncryptedData> xsecEncData(encrypter.encryptElement(doc->getDocumentElement(), ep, &xsecKep));

            string xsecBuffer, toolingBuffer;
            XMLHelper::serialize(xsecEncData->marshall(), xsecBuffer);
            XMLHelper::serialize(toolingEncData->marshall(), toolingBuffer);
            const char* cx = xsecBuffer.c_str();
            const char* ct = toolingBuffer.c_str();

            // The decrypted data is completely different. hmm.
            // TSM_ASSERT_EQUALS("Encrytped Data differs", cx, ct);
        }
    }

    void DSATest(const char* file, bool roundTripFails, bool nullTooling, bool nullXsec, bool verifyThrows) {

        string path = data_path + file;
        ifstream fs(path.c_str());
        ParserPool& parser = XMLToolingConfig::getConfig().getParser();
        DOMDocument* doc = parser.parse(fs);

        TS_ASSERT(doc != nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b != nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get() != nullptr);

        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));
        const scoped_ptr<DSIGKeyInfoList> xencKey(new DSIGKeyInfoList(env.get()));
        xencKey->loadListFromXML(doc->getDocumentElement());

        const scoped_ptr<X509Credential> toolingCred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", toolingCred.get() != nullptr);
        TSM_ASSERT("Expected null Private Key", toolingCred->getPrivateKey() == nullptr);
 
        const scoped_ptr<X509Credential> xsecCred(dynamic_cast<X509Credential*>(m_resolver->resolve(xencKey.get())));
        if (nullTooling ) {
            TSM_ASSERT_EQUALS("Expected null Public Key (tooling)", toolingCred->getPublicKey(), nullptr);
        }
        else {
            TSM_ASSERT("Expected non-null Public Key", toolingCred->getPublicKey() != nullptr);
            TSM_ASSERT_EQUALS("Expected DSA key", toolingCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_DSA_PUBLIC);
            const OpenSSLCryptoKeyDSA* toolingKeyInfoDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(toolingCred->getPublicKey());
            if (verifyThrows) {
                TSM_ASSERT_THROWS("Bad DSA key throws an assert", toolingKeyInfoDSA->verifyBase64Signature(m_toSign, 20, m_outSigDSA, m_sigLenDSA), XSECCryptoException);
            }
            else {
                bool toolingWorked = toolingKeyInfoDSA->verifyBase64Signature(m_toSign, 20, m_outSigDSA, m_sigLenDSA);
                if (roundTripFails) {
                    TSM_ASSERT("Round trip KeyInfo DSA worked (tooling)", !toolingWorked);
                }
                else {
                    TSM_ASSERT("Round trip KeyInfo DSA failed (tooling)", toolingWorked);
                }
            }
        }
        if (nullXsec) {
            if (xsecCred) {
                TSM_ASSERT_EQUALS("Expected null xsec Cred or Public Key", xsecCred->getPublicKey(), nullptr);
            }
        }
        else {
            TSM_ASSERT("Unable to resolve DSIGKeyInfoList into Credential.", xsecCred.get() != nullptr);
            TSM_ASSERT("Expected null Private Key", xsecCred->getPrivateKey() == nullptr);
            TSM_ASSERT("Expected non-null Public Key", xsecCred->getPublicKey() != nullptr);
            TSM_ASSERT_EQUALS("Expected DSA key", xsecCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_DSA_PUBLIC);
            const OpenSSLCryptoKeyDSA* xsecKeyInfoDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(xsecCred->getPublicKey());
            if (verifyThrows) {
                TSM_ASSERT_THROWS("Bad DSA key throws an assert", xsecKeyInfoDSA->verifyBase64Signature(m_toSign, 20, m_outSigDSA, m_sigLenDSA), XSECCryptoException);
            }
            else {
                bool xsecWorked = xsecKeyInfoDSA->verifyBase64Signature(m_toSign, 20, m_outSigDSA, m_sigLenDSA);
                if (roundTripFails) {
                    TSM_ASSERT("Round trip KeyInfo DSA worked (xsec)", !xsecWorked);
                }
                else {
                    TSM_ASSERT("Round trip KeyInfo DSA failed (xsec)", xsecWorked);
                }
            }
        }
    }


public:

    void testRSABadMod()
    {
        // Encryption Throws, but keys are present
        RSATest("RSABadMod.xml", true, false);
    }

    void testRSABadMod64()
    {
        // Encryption Throws, but keys are present
        RSATest("RSABadMod64.xml", true, false);
    }

    void testRSABadExp()
    {
        // Encryption "works", and keys are present
        RSATest("RSABadExp.xml", false, false);
    }

    void testRSABadExp64()
    {
        // Encryption "works", and keys are present
        RSATest("RSABadExp64.xml", false, false);
    }

    void testRSANullMod()
    {
        // Encryption throws, no keys
        RSATest("RSANullMod.xml", true, true);
    }

    void testRSANullExp()
    {
        // Encryption throws, no keys
        RSATest("RSANullExp.xml", true, true);
    }

    void testRSANullBoth()
    {
        // Encryption throws, no keys
        RSATest("RSANullBoth.xml", true, true);
    }

    void testRSAEmpty()
    {
        // Encryption throws, no keys
        RSATest("RSAEmpty.xml", true, true);
    }

    // DSA

    void testDSAGood()
    {
        // Round trip work, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature doesn't throw (both cases)
        DSATest("KeyInfoDSA.xml", false, false, false, false);
    }

    // P: tests
    // In all these cases the round trip fails.
    void testDSABadP()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature doesn't throw (both cases)
        DSATest("DSABadP.xml", true, false, false, false);
    }

    void testDSABadP64()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature doesn't throw (both cases)
        DSATest("DSABadP64.xml", true, false, false, false);
    }

    void testDSANoP()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANoP.xml", true, true, false, true);
    }

    void testDSANullP()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANullP.xml", true, true, false, true);
    }

    // Q: Tests
    void testDSABadQ()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws (xsec & tooling)
        DSATest("DSABadQ.xml", true, false, false, true);
    }

    void testDSABadQ64()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws (xsec & tooling)
        DSATest("DSABadQ64.xml", true, false, false, true);
    }

    void testDSANoQ()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANoQ.xml", true, true, false, true);
    }

    void testDSANoPQ()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANoQP.xml", true, false, false, true);
    }

    void testDSANullQ()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANullQ.xml", true, true, false, true);
    }

    void testDSANullPQ()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANullQP.xml", true, true, false, true);
    }

};