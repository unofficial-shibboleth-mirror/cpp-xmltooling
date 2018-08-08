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

using namespace xmlsignature;
using namespace xmlencryption;


class BadKeyInfoTest : public CxxTest::TestSuite {
    KeyInfoResolver* m_resolver;

public:
    BadKeyInfoTest() : m_resolver(nullptr) {}

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

private:
    void RSATest(const char* file, bool fails, ParserPool& parser = XMLToolingConfig::getConfig().getValidatingParser()) {

        string path=data_path + file;
        ifstream fs(path.c_str());
        // Non validating parser!
        DOMDocument* doc=parser.parse(fs);

        TS_ASSERT(doc!=nullptr);

        const XMLObjectBuilder* b = XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);
        const scoped_ptr<KeyInfo> kiObject(dynamic_cast<KeyInfo*>(b->buildFromDocument(doc)));
        TS_ASSERT(kiObject.get()!=nullptr);

        const scoped_ptr<Credential> toolingCred(dynamic_cast<Credential*>(m_resolver->resolve(kiObject.get())));
        TSM_ASSERT("Unable to resolve KeyInfo into Credential.", toolingCred.get()!=nullptr);
        TSM_ASSERT("Expected null Private Key", toolingCred->getPrivateKey()==nullptr);
        TSM_ASSERT("Expected non-null Public Key", toolingCred->getPublicKey()!=nullptr);
        TSM_ASSERT_EQUALS("Expected RSA key", toolingCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);

        const scoped_ptr<const XSECEnv> env(new XSECEnv(doc));
        const scoped_ptr<DSIGKeyInfoList> xencKey(new DSIGKeyInfoList(env.get()));
        xencKey->loadListFromXML(doc->getDocumentElement());

        const scoped_ptr<Credential> xsecCred(dynamic_cast<Credential*>(m_resolver->resolve(xencKey.get())));
        TSM_ASSERT("Unable to resolve DSIGKeyInfoList into Credential.", xsecCred.get() != nullptr);
        TSM_ASSERT("Expected null Private Key", xsecCred->getPrivateKey() == nullptr);
        TSM_ASSERT("Expected non-null Public Key", xsecCred->getPublicKey() != nullptr);
        TSM_ASSERT_EQUALS("Expected RSA key", xsecCred->getPublicKey()->getKeyType(), XSECCryptoKey::KEY_RSA_PUBLIC);

        Encrypter encrypter;
        Encrypter::EncryptionParams ep;
        Encrypter::KeyEncryptionParams xsecKep(*xsecCred.get());
        Encrypter::KeyEncryptionParams toolingKep(*toolingCred.get());
        //
        if (fails) {
            TSM_ASSERT_THROWS("Bad RSA key throws an assert", encrypter.encryptElement(doc->getDocumentElement(), ep, &xsecKep), EncryptionException);
            TSM_ASSERT_THROWS("Bad RSA key throws an assert", encrypter.encryptElement(doc->getDocumentElement(), ep, &toolingKep), EncryptionException);
        }
        else {
            scoped_ptr<EncryptedData> toolingEncData(encrypter.encryptElement(doc->getDocumentElement(), ep, &toolingKep));
            scoped_ptr<EncryptedData> xsecEncData(encrypter.encryptElement(doc->getDocumentElement(), ep, &xsecKep));

            string xsecBuffer, toolingBuffer;
            XMLHelper::serialize(xsecEncData->marshall(), xsecBuffer);
            XMLHelper::serialize(toolingEncData->marshall(), toolingBuffer);
            const char* cx= xsecBuffer.c_str();
            const char* ct= toolingBuffer.c_str();

            // The decrypted data is completely different. hmm.
            // TSM_ASSERT_EQUALS("Encrytped Data differs", cx, ct);
        }

    }

public:

    void testRSABadMod()
    {
        RSATest("RSABadMod.xml", true, XMLToolingConfig::getConfig().getParser());
    }

    void testRSABadMod64()
    {
        RSATest("RSABadMod64.xml", true);
    }

    void testRSABadExp()
    {
        RSATest("RSABadExp.xml", false, XMLToolingConfig::getConfig().getParser());
    }

    void testRSABadExp64()
    {
        RSATest("RSABadExp64.xml", false);
    }

};
