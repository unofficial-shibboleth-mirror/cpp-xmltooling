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

#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/signature/ContentReference.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/SignatureValidator.h>

#include <fstream>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/enc/XSECCryptoKeyDSA.hpp>
#include <xsec/enc/XSECCryptoKeyEC.hpp>
#include <xsec/enc/XSECCryptoKeyRSA.hpp>
#include <openssl/opensslv.h>

class TestContext : public ContentReference
{
    XMLCh* m_uri;
    
public:
    TestContext(const XMLCh* uri) {
        m_uri=XMLString::replicate(uri);
    }
    
    virtual ~TestContext() {
        XMLString::release(&m_uri);
    }

    void createReferences(DSIGSignature* sig) {
        DSIGReference* ref=sig->createReference(m_uri, DSIGConstants::s_unicodeStrURISHA1);
        ref->appendEnvelopedSignatureTransform();
        ref->appendCanonicalizationTransform(DSIGConstants::s_unicodeStrURIEXC_C14N_NOC);
    }
};

class TestValidator : public SignatureValidator
{
    XMLCh* m_uri;
    
public:
    TestValidator(const XMLCh* uri, const Credential* credential) : SignatureValidator(credential) {
        m_uri=XMLString::replicate(uri);
    }
    
    virtual ~TestValidator() {
        XMLString::release(&m_uri);
    }

    void validate(const Signature* sigObj) const {
        DSIGSignature* sig=sigObj->getXMLSignature();
        if (!sig)
            throw SignatureException("Only a marshalled Signature object can be verified.");
        const XMLCh* uri=sig->getReferenceList()->item(0)->getURI();
        TSM_ASSERT_SAME_DATA("Reference URI does not match.",uri,m_uri,XMLString::stringLen(uri));
        SignatureValidator::validate(sigObj);
    }
};

class SignatureTest : public CxxTest::TestSuite {
    CredentialResolver* m_resolver;
public:
    void setUp() {
        m_resolver=nullptr;
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE,SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::registerBuilder(qname, new SimpleXMLObjectBuilder());
        XMLObjectBuilder::registerBuilder(qtype, new SimpleXMLObjectBuilder());

        string config = data_path + "FilesystemCredentialResolver.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);
        m_resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
            CHAINING_CREDENTIAL_RESOLVER,doc->getDocumentElement(), false
            );
    }

    void tearDown() {
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE,SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::deregisterBuilder(qname);
        XMLObjectBuilder::deregisterBuilder(qtype);
        delete m_resolver;
    }

    void testOpenSSLEC() {
#ifdef XSEC_OPENSSL_HAVE_EC

        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("EC");

        Locker locker(m_resolver);
        const XSECCryptoKeyEC* ecCred = dynamic_cast<const XSECCryptoKeyEC*>(m_resolver->resolve(&cc)->getPrivateKey());

        unsigned char toSign[] = "NibbleAHappyWartHog";
        const int bufferSize = 1024;
        char outSig[bufferSize] = {0};
        unsigned int len = ecCred->signBase64SignatureDSA(toSign, sizeof(toSign), &outSig[0], bufferSize);
        bool worked = ecCred->verifyBase64SignatureDSA(toSign, sizeof(toSign), &outSig[0], len);
        TSM_ASSERT("EC Round Trip Signature Failed", worked);

        char knownGoodSig[] = "AkXRDL2H2I+fozXnuHKYa4+UE/k+AnhOLp2AY5d8lAqciZ5wdObHbifX\n";
        unsigned int knownGoodSigSize=0x38;

        worked = ecCred->verifyBase64SignatureDSA(toSign, sizeof(toSign), knownGoodSig, knownGoodSigSize);
        TSM_ASSERT("EC Canned Signature Failed", worked);

#endif
    }

    void testOpenSSLRSA() {
        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("RSA");

        Locker locker(m_resolver);
        const XSECCryptoKeyRSA* rsaCred = dynamic_cast<const XSECCryptoKeyRSA*>(m_resolver->resolve(&cc)->getPrivateKey());

        unsigned char toSign[] = "Nibble A Happy WartHog";
        const int bufferSize = 1024;
        char outSig[bufferSize] = {0};
        const char knownGoodSig[] = "jCNgXSZOuKATdqkws11rSA0+7kXu0jpLtH3p4H+hgFJGhXyzEtkv09YG5UvMYxaO\n"
                                    "/pktalyEYtfAaQL3cs01TFs+92cI6ytIrQumroQeRpc+EJuj43RWaFqlMtKj5qkS\n"
                                    "3Q03BRauYYexXQBoP/K5irtkyLWEun4tVhIePOUvl90=\n";
        unsigned int len;

        len = rsaCred->signSHA1PKCS1Base64Signature(toSign, 20, &outSig[0], bufferSize, XSECCryptoHash::HASH_SHA1);

        const int diffLen = memcmp(outSig, knownGoodSig, len);
        TSM_ASSERT("RSA Signature Failed", diffLen == 0);
    }

    void testOpenSSLDSA() {
        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("DSA");

        Locker locker(m_resolver);
        const XSECCryptoKeyDSA* dsaCred = dynamic_cast<const XSECCryptoKeyDSA*>(m_resolver->resolve(&cc)->getPrivateKey());

        unsigned char toSign[] = "NibbleAHappyWartHog";
        const int bufferSize = 1024;
        char outSig[bufferSize] = {0};
        unsigned int len = dsaCred->signBase64Signature(toSign, sizeof(toSign), &outSig[0], bufferSize);
        bool worked = dsaCred->verifyBase64Signature(toSign, sizeof(toSign), &outSig[0], len);
        TSM_ASSERT("DSA Round Trip Signature Failed", worked);

        char knownGoodSig[] = "bjl/jCGFdRgs0Ar5DKQkE9jPZFSXU5Wm2SKMzur4TSzoQmTe82WC8A==\012";
        unsigned int knownGoodSigSize=0x39;

        worked = dsaCred->verifyBase64Signature(toSign, sizeof(toSign), knownGoodSig, knownGoodSigSize);
        TSM_ASSERT("DSA Canned Signature Failed", worked);
    }

    void testSignatureDSA() {
#ifdef XSEC_OPENSSL_HAVE_SHA2
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        const SimpleXMLObjectBuilder* b=dynamic_cast<const SimpleXMLObjectBuilder*>(XMLObjectBuilder::getBuilder(qname));
        TS_ASSERT(b!=nullptr);

        scoped_ptr<SimpleXMLObject> sxObject(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        TS_ASSERT(sxObject.get()!=nullptr);
        VectorOf(SimpleXMLObject) kids=sxObject->getSimpleXMLObjects();
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));

        // Test some collection stuff
        auto_ptr_XMLCh foo("Foo");
        auto_ptr_XMLCh bar("Bar");
        kids.begin()->setId(foo.get());
        kids[1]->setValue(bar.get());

        // Append a Signature.
        Signature* sig=SignatureBuilder::buildSignature();
        sig->setSignatureAlgorithm(DSIGConstants::s_unicodeStrURIDSA_SHA256);
        sxObject->setSignature(sig);

        sig->setContentReference(new TestContext(&chNull));

        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("DSA");

        Locker locker(m_resolver);
        const Credential* cred = m_resolver->resolve(&cc);
        TSM_ASSERT("Retrieved credential was null", cred!=nullptr);

        DOMElement* rootElement = nullptr;
        try {
            vector<Signature*> sigs(1,sig);
            rootElement=sxObject->marshall((DOMDocument*)nullptr,&sigs,cred);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }

        string buf;
        XMLHelper::serialize(rootElement, buf);

        istringstream in(buf);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        scoped_ptr<SimpleXMLObject> sxObject2(dynamic_cast<SimpleXMLObject*>(b->buildFromDocument(doc)));
        TS_ASSERT(sxObject2.get()!=nullptr);
        TS_ASSERT(sxObject2->getSignature()!=nullptr);

        try {
            TestValidator tv(&chNull, cred);
            tv.validate(sxObject2->getSignature());
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
#endif
    }


    void testSignatureEC() {
#ifdef XSEC_OPENSSL_HAVE_EC
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        const SimpleXMLObjectBuilder* b=dynamic_cast<const SimpleXMLObjectBuilder*>(XMLObjectBuilder::getBuilder(qname));
        TS_ASSERT(b!=nullptr);

        scoped_ptr<SimpleXMLObject> sxObject(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        TS_ASSERT(sxObject.get()!=nullptr);
        VectorOf(SimpleXMLObject) kids=sxObject->getSimpleXMLObjects();
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));

        // Test some collection stuff
        auto_ptr_XMLCh foo("Foo");
        auto_ptr_XMLCh bar("Bar");
        kids.begin()->setId(foo.get());
        kids[1]->setValue(bar.get());

        // Append a Signature.
        Signature* sig=SignatureBuilder::buildSignature();
        sig->setSignatureAlgorithm(DSIGConstants::s_unicodeStrURIECDSA_SHA1);
        sxObject->setSignature(sig);

        sig->setContentReference(new TestContext(&chNull));

        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("EC");

        Locker locker(m_resolver);
        const Credential* cred = m_resolver->resolve(&cc);
        TSM_ASSERT("Retrieved credential was null", cred!=nullptr);

        DOMElement* rootElement = nullptr;
        try {
            vector<Signature*> sigs(1,sig);
            rootElement=sxObject->marshall((DOMDocument*)nullptr,&sigs,cred);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }

        string buf;
        XMLHelper::serialize(rootElement, buf);

        istringstream in(buf);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        scoped_ptr<SimpleXMLObject> sxObject2(dynamic_cast<SimpleXMLObject*>(b->buildFromDocument(doc)));
        TS_ASSERT(sxObject2.get()!=nullptr);
        TS_ASSERT(sxObject2->getSignature()!=nullptr);

        try {
            TestValidator tv(&chNull, cred);
            tv.validate(sxObject2->getSignature());
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
#endif
    }

    void testSignatureRSA() {
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        const SimpleXMLObjectBuilder* b=dynamic_cast<const SimpleXMLObjectBuilder*>(XMLObjectBuilder::getBuilder(qname));
        TS_ASSERT(b!=nullptr);
        
        scoped_ptr<SimpleXMLObject> sxObject(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        TS_ASSERT(sxObject.get()!=nullptr);
        VectorOf(SimpleXMLObject) kids=sxObject->getSimpleXMLObjects();
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        
        // Test some collection stuff
        auto_ptr_XMLCh foo("Foo");
        auto_ptr_XMLCh bar("Bar");
        kids.begin()->setId(foo.get());
        kids[1]->setValue(bar.get());
        
        // Append a Signature.
        Signature* sig=SignatureBuilder::buildSignature();
        sxObject->setSignature(sig);
        sig->setContentReference(new TestContext(&chNull));

        CredentialCriteria cc;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        cc.setKeyAlgorithm("RSA");

        Locker locker(m_resolver);
        const Credential* cred = m_resolver->resolve(&cc);
        TSM_ASSERT("Retrieved credential was null", cred!=nullptr);
        
        DOMElement* rootElement = nullptr;
        try {
            vector<Signature*> sigs(1,sig);
            rootElement=sxObject->marshall((DOMDocument*)nullptr,&sigs,cred);
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
        
        string buf;
        XMLHelper::serialize(rootElement, buf);
        //TS_TRACE(buf.c_str());

        istringstream in(buf);
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        scoped_ptr<SimpleXMLObject> sxObject2(dynamic_cast<SimpleXMLObject*>(b->buildFromDocument(doc)));
        TS_ASSERT(sxObject2.get()!=nullptr);
        TS_ASSERT(sxObject2->getSignature()!=nullptr);
        
        try {
            TestValidator tv(&chNull, cred);
            tv.validate(sxObject2->getSignature());
        }
        catch (XMLToolingException& e) {
            TS_TRACE(e.what());
            throw;
        }
    }

};
