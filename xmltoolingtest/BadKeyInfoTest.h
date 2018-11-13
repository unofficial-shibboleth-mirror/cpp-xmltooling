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
    unsigned char m_toSign[23];
    char m_outSigDSA[SIGBUFFER_SIZE];
    char m_outSigEC[SIGBUFFER_SIZE];
    unsigned int m_sigLenDSA;
    unsigned int m_sigLenEC;
    string m_keyInfoPath;

    KeyInfoResolver* getResolver(string fileName) {
        string config = data_path + fileName;
        ifstream in(config.c_str());
        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        return XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(
                        INLINE_KEYINFO_RESOLVER, doc->getDocumentElement(), false
        );
    }

public:
    BadKeyInfoTest() : m_resolver(nullptr), m_sigLenDSA(0), m_sigLenEC(0) {
        memset(m_outSigDSA, 0, SIGBUFFER_SIZE);
        memset(m_outSigEC, 0, SIGBUFFER_SIZE);
        strcpy((char*)m_toSign, "Nibble A Happy WartHog");
    }

    void setUp() {
        XMLObjectBuilder::registerDefaultBuilder(new UnknownElementBuilder());

        m_keyInfoPath = data_path + "BadKeyInfo/";
        m_resolver = getResolver("InlineKeyResolver.xml");

        if (m_sigLenEC == 0 || m_sigLenDSA == 0) {
            // Resolver for DSA and RSA signatures
            const string config = data_path + "FilesystemCredentialResolver.xml";
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
                m_sigLenEC = 1;
#endif
            }
        }
        // Marshalling  Setup
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE, SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE, SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::registerBuilder(qname, new SimpleXMLObjectBuilder());
        XMLObjectBuilder::registerBuilder(qtype, new SimpleXMLObjectBuilder());
    }

    void tearDown() {
        delete m_resolver;
        m_resolver = nullptr;

        xmltooling::QName qname(SimpleXMLObject::NAMESPACE, SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE, SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::deregisterBuilder(qname);

        XMLObjectBuilder::deregisterDefaultBuilder();
    }

private:
    void RSATest(const char* file, bool encryptionThrows, bool nullKeys) {

        string path = m_keyInfoPath + file;
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

    void DSATest(const char* file, bool roundTripFails, bool nullTooling, bool nullXsec, bool verifyOrLoadThrows) {

        string path = m_keyInfoPath + file;
        ifstream fs(path.c_str());
        ParserPool& parser = XMLToolingConfig::getConfig().getParser();
        DOMDocument* doc = parser.parse(fs);

        TS_ASSERT(doc != nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b != nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get() != nullptr);

        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));

        const scoped_ptr<Credential> toolingCred(dynamic_cast<Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", toolingCred.get() != nullptr);
        TSM_ASSERT("Expected null Private Key", toolingCred->getPrivateKey() == nullptr);

        if (nullTooling) {
            TSM_ASSERT_EQUALS("Expected null Public Key (tooling)", toolingCred->getPublicKey(), nullptr);
        }
        else {
            TSM_ASSERT("Expected non-null Public Key", toolingCred->getPublicKey() != nullptr);
            TSM_ASSERT_EQUALS("Expected DSA key", toolingCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_DSA_PUBLIC);
            const OpenSSLCryptoKeyDSA* toolingKeyInfoDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(toolingCred->getPublicKey());
            if (verifyOrLoadThrows) {
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

        const scoped_ptr<DSIGKeyInfoList> xsecKey(new DSIGKeyInfoList(env.get()));
        if (nullXsec && verifyOrLoadThrows) {
            TSM_ASSERT_THROWS("Bad DSA key throws an assert during Load", xsecKey->loadListFromXML(doc->getDocumentElement()), XSECCryptoException);
        }
        else {
            xsecKey->loadListFromXML(doc->getDocumentElement());
            const scoped_ptr<Credential> xsecCred(dynamic_cast<Credential*>(m_resolver->resolve(xsecKey.get())));

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
                if (verifyOrLoadThrows) {
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
    }

    void KeyRefTest(const char* file, bool works) {
        const scoped_ptr<KeyInfoResolver> resolver(getResolver("BadKeyInfo/ResolverRefs.xml"));

        const string path = m_keyInfoPath + file;
        ifstream fs(path.c_str());
        ParserPool& parser = XMLToolingConfig::getConfig().getParser();
        DOMDocument* doc = parser.parse(fs);
        TS_ASSERT(doc != nullptr);

        // XSEC - no support
        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));
        const scoped_ptr<DSIGKeyInfoList> xsecKey(new DSIGKeyInfoList(env.get()));
        xsecKey->loadListFromXML(doc->getDocumentElement());
        const scoped_ptr<Credential> xsecCred(dynamic_cast<Credential*>(resolver->resolve(xsecKey.get())));
        TS_ASSERT(xsecCred.get() == nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b != nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get() != nullptr);

        const scoped_ptr<Credential> toolingCred(dynamic_cast<Credential*>(resolver->resolve(kiObject.get())));
        if (!works) {
            TS_ASSERT(toolingCred.get() == nullptr);
            return;
        }

        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", toolingCred.get() != nullptr);
        TSM_ASSERT("Expected null Private Key", toolingCred->getPrivateKey() == nullptr);

        TSM_ASSERT("Expected non-null Public Key", toolingCred->getPublicKey() != nullptr);
        TSM_ASSERT_EQUALS("Expected DSA key", toolingCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_DSA_PUBLIC);
        const OpenSSLCryptoKeyDSA* toolingKeyInfoDSA = dynamic_cast<const OpenSSLCryptoKeyDSA*>(toolingCred->getPublicKey());
        bool toolingWorked = toolingKeyInfoDSA->verifyBase64Signature(m_toSign, 20, m_outSigDSA, m_sigLenDSA);
        TSM_ASSERT("Round trip KeyInfo DSA failed (tooling)", toolingWorked);

    }

#ifdef XSEC_OPENSSL_HAVE_EC

    void ECTest(const char* file, bool roundTripFails, bool xsecLoadThrows, bool resolveFails) {

        const string path = m_keyInfoPath + file;
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
        if (xsecLoadThrows) {
            TSM_ASSERT_THROWS("Bad EC key throws during load", xencKey->loadListFromXML(doc->getDocumentElement()), XSECException);
        }
        else {
            xencKey->loadListFromXML(doc->getDocumentElement());
            const scoped_ptr<X509Credential> xsecCred(dynamic_cast<X509Credential*>(m_resolver->resolve(xencKey.get())));
            if (resolveFails) {
                TSM_ASSERT("XsecCred was non null", xsecCred.get() == nullptr)
            }
            else {
                TSM_ASSERT("Unable to resolve DSIGKeyInfoList into Credential.", xsecCred.get() != nullptr);

                TSM_ASSERT("Expected null Private Key", xsecCred->getPrivateKey() == nullptr);
                TSM_ASSERT("Expected non-null Public Key", xsecCred->getPublicKey() != nullptr);
                TSM_ASSERT_EQUALS("Expected EC key", xsecCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_EC_PUBLIC);
                const OpenSSLCryptoKeyEC* xsecKeyInfoEC = dynamic_cast<const OpenSSLCryptoKeyEC*>(xsecCred->getPublicKey());
                bool xsecWorked = xsecKeyInfoEC->verifyBase64SignatureDSA(m_toSign, 20, m_outSigEC, m_sigLenEC);
                if (roundTripFails) {
                    TSM_ASSERT("Round trip KeyInfo EC worked (xsec)", !xsecWorked);
                }
                else {
                    TSM_ASSERT("Round trip KeyInfo EC failed (xsec)", xsecWorked);
                }
            }
        }
        const scoped_ptr<X509Credential> toolingCred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        if (resolveFails) {
            TSM_ASSERT("ToolCred was non null", toolingCred.get() == nullptr)
        }
        else {
            TSM_ASSERT("Unable to resolve KeyInfo into Credential.", toolingCred.get() != nullptr);
            TSM_ASSERT("Expected null Private Key", toolingCred->getPrivateKey() == nullptr);
            TSM_ASSERT("Expected non-null Public Key", toolingCred->getPublicKey() != nullptr);
            TSM_ASSERT_EQUALS("Expected EC key", toolingCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_EC_PUBLIC);
            const OpenSSLCryptoKeyEC* toolingKeyInfoEC = dynamic_cast<const OpenSSLCryptoKeyEC*>(toolingCred->getPublicKey());
            bool toolingWorked = toolingKeyInfoEC->verifyBase64SignatureDSA(m_toSign, 20, m_outSigEC, m_sigLenEC);
            if (roundTripFails) {
                TSM_ASSERT("Round trip KeyInfo EC worked (tooling)", !toolingWorked);
            }
            else {
                TSM_ASSERT("Round trip KeyInfo EC failed (tooling)", toolingWorked);
            }
        }
    }

    void ECTestParam(const char* file) {
        const string path = m_keyInfoPath + file;
        ifstream fs(path.c_str());
        ParserPool& parser = XMLToolingConfig::getConfig().getValidatingParser();
        DOMDocument* doc = parser.parse(fs);

        TS_ASSERT(doc != nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b != nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get() != nullptr);

        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));
        const scoped_ptr<DSIGKeyInfoList> xencKey(new DSIGKeyInfoList(env.get()));
        TSM_ASSERT_THROWS("Bad EC key throws during load", xencKey->loadListFromXML(doc->getDocumentElement()), XSECException);
        const scoped_ptr<X509Credential> toolingCred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("ToolCred was non null", toolingCred.get() == nullptr)
    }

#else
#define ECTest(file, a, b, c) return
#define ECTestParam(file) return
#endif

    void DERTest(const char* file, bool xsecLoadThrows) {

        const string path = m_keyInfoPath + file;
        ifstream fs(path.c_str());
        ParserPool& parser = XMLToolingConfig::getConfig().getValidatingParser();
        DOMDocument* doc = parser.parse(fs);

        TS_ASSERT(doc != nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b != nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get() != nullptr);

        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));
        const scoped_ptr<DSIGKeyInfoList> xencKey(new DSIGKeyInfoList(env.get()));
        if (xsecLoadThrows) {
            TSM_ASSERT_THROWS("Bad EC key throws during load", xencKey->loadListFromXML(doc->getDocumentElement()), XSECException);
        }
        else {
            xencKey->loadListFromXML(doc->getDocumentElement());
            const scoped_ptr<X509Credential> xsecCred(dynamic_cast<X509Credential*>(m_resolver->resolve(xencKey.get())));
            TSM_ASSERT("XsecCred was non null", xsecCred.get() == nullptr)
        }
        const scoped_ptr<X509Credential> toolingCred(dynamic_cast<X509Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("ToolCred was non null", toolingCred.get() == nullptr)
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
        DSATest("../KeyInfoDSA.xml", false, false, false, false);
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

    // G:
    void testDSABadG()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws doesn't throw (both cases)
        DSATest("DSABadG.xml", true, false, false, false);
    }

    void testDSABadG64()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws doesn't throw (both cases)
        DSATest("DSABadG64.xml", true, false, false, false);
    }

    void testDSANoG()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANoG.xml", true, false, false, true);
    }

    void testDSANullG()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature throws (xsec)
        DSATest("DSANullG.xml", true, true, false, true);
    }

    // J:
    void testDSABadJ()
    {
        // Round trip works, Keys returned nothing throws
        DSATest("DSABadJ.xml", false, false, false, false);
    }

    void testDSABadJ64()
    {
        // Round trip works, Keys returned nothing throws
        DSATest("DSABadJ64.xml", false, false, false, false);
    }

    // Y:
    void testDSABadY()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws doesn't throw (both cases)
        DSATest("DSABadY.xml", true, false, false, false);
    }

    void testDSABadY64()
    {
        // Round trip fails, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature throws doesn't throw (both cases)
        DSATest("DSABadY64.xml", true, false, false, false);
    }

    void testDSANoY()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns NO public key
        DSATest("DSANoY.xml", true, true, true, false);
    }

    void testDSANullY()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns NO public key
        DSATest("DSANullY.xml", true, true, true, false);
    }

    void testDSANullJ()
    {
        // Round trip works (xsec), XmlTooling returns NO public key, Santuario returns a public key, verifyBase64Signature doesn't throw (xsec)
        DSATest("DSANullJ.xml", false, true, false, false);
    }

    // Seed: counter
    void testDSASeedCounter()
    {
        // Works
        DSATest("DSASeedCounter.xml", false, false, false, false);
    }

    void testDSABadSeedCounter()
    {
        // Works
        DSATest("DSABadSeedCounter.xml", false, false, false, false);
    }

    void testDSABadSeedCounter64()
    {
        // Works
        DSATest("DSABadSeedCounter64.xml", false, false, false, false);
    }

    void testDSABadSeed()
    {
        // Works
        DSATest("DSABadSeed.xml", false, false, false, false);
    }

    void testDSANoSeed()
    {
        // Works
        DSATest("DSANoSeed.xml", false, true, false, false);
    }

    void testDSANullSeed()
    {
        // Works
        DSATest("DSANullSeed.xml", false, true, false, false);
    }

    void testDSABadCounter()
    {
        // Works
        DSATest("DSABadCounter.xml", false, false, false, false);
    }

    void testDSANoCounter()
    {
        // Works xsec, No XMLTooling Key
        DSATest("DSANoCounter.xml", false, true, false, false);
    }

    void testDSANullCounter()
    {
        // Works xsec, No XMLTooling Key
        DSATest("DSANullCounter.xml", false, true, false, false);
    }

    void testECGood()
    {
        // Works !  All keys available, no exceptions, no failures
        ECTest("../KeyInfoEC.xml", false, false, false);
    }

    void testECBadKey()
    {
        // Fails, No exception from santuario Load, but resolve fails
        ECTest("ECBadKey.xml", false, false, true);
    }

    void testECBadKey64()
    {
        // Fails, No exception from santuario Load, but resolve fails
        ECTest("ECBadKey.xml", false, false, true);
    }

    void testECNullKey()
    {
        // Fails, Exception from santuario Load and Shib resolve fails
        ECTest("ECNullKey.xml", false, true, true);
    }

    void testECNoKey()
    {
        // Fails, Exception from santuario Load and Shib resolve fails
        ECTest("ECNoKey.xml", false, true, true);
    }

    void testECBadCurve()
    {
        // Fails, No exception from santuario Load, but resolve fails
        ECTest("ECBadCurve.xml", false, false, true);
    }

    void testECNullCurve()
    {
        // Fails, No exception from santuario Load, but resolve fails
        ECTest("ECNullCurve.xml", false, false, true);
    }

    void testECNoCurve()
    {
        // Fails, Exception from santuario Load and Shib resolve fails
        ECTest("ECNoCurve.xml", false, true, true);
    }

    void testECParamPrime()
    {
        ECTestParam("ECParamPrime.xml");
    }

    void testECParamNone()
    {
        ECTestParam("ECParamNone.xml");
    }


    void testECParamPnB()
    {
        ECTestParam("ECParamPnB.xml");
    }

    void testECParamTnb()
    {
        ECTestParam("ECParamTnB.xml");
    }

    void testECParamGnB()
    {
        ECTestParam("ECParamGnB.xml");
    }

    void testDERBad()
    {
        DERTest("DERValueBad.xml", false);
    }

    void testDERBad64()
    {
        DERTest("DERValueBad64.xml", false);
    }

    void testDERNull()
    {
        DERTest("DERValueNull.xml", true);
    }

    // X509Data
    void testX509Good()
    {
        // Round trip work, XmlTooling returns a public key, Santuario returns a public key, verifyBase64Signature doesn't throw (both cases)
        DSATest("X509Good.xml", false, false, false, false);
    }

    void testX509Bad()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns no public key because it throws
        DSATest("X509Bad.xml", true, true, true, true);
    }

    void testX509Bad64()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns no public key because it throws
        DSATest("X509Bad64.xml", true, true, true, true);
    }

    void testX509Null()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns NO public key
        DSATest("X509Null.xml", true, true, true, false);
    }

    void testX509None()
    {
        // Round trip fails, XmlTooling returns NO public key, Santuario returns NO public key
        DSATest("X509None.xml", true, true, true, false);
    }

    // KeyInfoReference
    void testRefRecursive()
    {
       KeyRefTest("KeyInfoRefRecursive.xml", false);
    }

    void testRefWrongURI()
    {
        KeyRefTest("KeyInfoRefWrongURI.xml", false);
    }

    void testRefMissing()
    {
        KeyRefTest("KeyInfoRefMissing.xml", false);
    }

    void testRefChild()
    {
        KeyRefTest("KeyInfoRefChild.xml", true);
    }
};
