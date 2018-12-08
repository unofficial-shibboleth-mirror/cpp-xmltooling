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

#include <xmltooling/encryption/Decrypter.h>
#include <xmltooling/encryption/Encrypter.h>
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>

#include <fstream>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>

using namespace xmlencryption;

class EncryptionTest : public CxxTest::TestSuite {
    CredentialResolver* m_resolver;
    DOMDocument* m_complexObject;
public:
    void setUp() {
        m_resolver=nullptr;
        const string config = data_path + "FilesystemCredentialResolver.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);
        m_resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
            CHAINING_CREDENTIAL_RESOLVER, doc->getDocumentElement(), false
            );
        XMLObjectBuilder::registerDefaultBuilder(new UnknownElementBuilder());

        const string path=data_path + "ComplexXMLObject.xml";
        ifstream fs(path.c_str());
        m_complexObject=XMLToolingConfig::getConfig().getParser().parse(fs);

        // Marshalling  Setup
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE, SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE, SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::registerBuilder(qname, new SimpleXMLObjectBuilder());
        XMLObjectBuilder::registerBuilder(qtype, new SimpleXMLObjectBuilder());
    }

    void tearDown() {
        XMLObjectBuilder::deregisterDefaultBuilder();
        delete m_resolver;
        m_complexObject->release();

        xmltooling::QName qname(SimpleXMLObject::NAMESPACE, SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE, SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::deregisterBuilder(qname);
        XMLObjectBuilder::deregisterBuilder(qtype);
    }

    void testEncryption() {
        TS_ASSERT(m_complexObject != nullptr);
        try {
            CredentialCriteria cc;
            cc.setUsage(Credential::ENCRYPTION_CREDENTIAL);
            Locker locker(m_resolver);
            const Credential* cred=m_resolver->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred!=nullptr);

            Encrypter encrypter;
            Encrypter::EncryptionParams ep;
            Encrypter::KeyEncryptionParams kep(*cred);
            scoped_ptr<EncryptedData> encData(encrypter.encryptElement(m_complexObject->getDocumentElement(),ep,&kep));

            string buf;
            XMLHelper::serialize(encData->marshall(), buf);
            //TS_TRACE(buf.c_str());
            istringstream is(buf);
            DOMDocument* doc2=XMLToolingConfig::getConfig().getValidatingParser().parse(is);
            scoped_ptr<EncryptedData> encData2(
                dynamic_cast<EncryptedData*>(XMLObjectBuilder::buildOneFromElement(doc2->getDocumentElement(),true))
                );

            Decrypter decrypter(m_resolver);
            DOMDocumentFragment* frag = decrypter.decryptData(*encData2.get());
            XMLHelper::serialize(static_cast<DOMElement*>(frag->getFirstChild()), buf);
            //TS_TRACE(buf.c_str());
            TS_ASSERT(m_complexObject->getDocumentElement()->isEqualNode(frag->getFirstChild()));
            frag->release();
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

    void preEncrypted(const string path, const bool fails) {
        TS_ASSERT(m_complexObject != nullptr);

        try {
            CredentialCriteria cc;
            cc.setUsage(Credential::ENCRYPTION_CREDENTIAL);
            Locker locker(m_resolver);
            const Credential* cred=m_resolver->resolve(&cc);
            TSM_ASSERT("Retrieved credential was null", cred != nullptr);

            const string encDataPath = data_path + path;
            ifstream is(encDataPath.c_str());

            DOMDocument* doc2=XMLToolingConfig::getConfig().getParser().parse(is);
            scoped_ptr<EncryptedData> encData2(
                dynamic_cast<EncryptedData*>(XMLObjectBuilder::buildOneFromElement(doc2->getDocumentElement(), true))
            );

            Decrypter decrypter(m_resolver);
            if (fails) {
                TSM_ASSERT_THROWS("encryption should fail", decrypter.decryptData(*encData2.get()), XMLToolingException);
                return;
            }
            DOMDocumentFragment* frag = decrypter.decryptData(*encData2.get());
            string buf;
            XMLHelper::serialize(static_cast<DOMElement*>(frag->getFirstChild()), buf);
            // TS_TRACE(buf.c_str());
            TS_ASSERT(m_complexObject->getDocumentElement()->isEqualNode(frag->getFirstChild()));
            frag->release();
        } catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

    void testPreEncrypted()
    {
        preEncrypted("BadKeyInfo/encData.xml", false);
    }

    void testRetrieval()
    {
        preEncrypted("BadKeyInfo/retrievalChild.xml", false);
    }

    void testRetrievalBadURI()
    {
        preEncrypted("BadKeyInfo/retrievalBadURI.xml", true);
    }

    void testRetrievalMissingType()
    {
        preEncrypted("BadKeyInfo/retrievalMissingType.xml", true);
    }

    void testRetrievalEmpty()
    {
        preEncrypted("BadKeyInfo/retrievalEmpty.xml", true);
    }

};
