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
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/TrustEngine.h>
#include <xsec/enc/XSECCryptoX509.hpp>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/security/X509TrustEngine.h>
#include <fstream>

class ExplicitKeyTrustEngineTest : public CxxTest::TestSuite {

private:
    X509TrustEngine* m_trustEngine;
    CredentialResolver *m_resolver;

public:

    void setUp() {
        m_resolver=nullptr;
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE,SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::registerBuilder(qname, new SimpleXMLObjectBuilder());
        XMLObjectBuilder::registerBuilder(qtype, new SimpleXMLObjectBuilder());

        string config = data_path + "FilesystemCredentialResolverCertOnly.xml";
        ifstream inFsCred(config.c_str());
        DOMDocument* docFsCred=XMLToolingConfig::getConfig().getParser().parse(inFsCred);
        XercesJanitor<DOMDocument> janitorFsCred(docFsCred);
        m_resolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
            CHAINING_CREDENTIAL_RESOLVER, docFsCred->getDocumentElement(), false
            );

        config = data_path + "ExplicitKeyTrustEngine.xml";
        ifstream inTrustEngine(config.c_str());
        DOMDocument* docTrustEngine=XMLToolingConfig::getConfig().getParser().parse(inTrustEngine);
        XercesJanitor<DOMDocument> janitor(docTrustEngine);

        TrustEngine *trustEngine =
            XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(
                EXPLICIT_KEY_TRUSTENGINE, docTrustEngine->getDocumentElement(), false
                );

        m_trustEngine = dynamic_cast<X509TrustEngine*>(trustEngine);

    }

    void tearDown() {
        xmltooling::QName qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME);
        xmltooling::QName qtype(SimpleXMLObject::NAMESPACE,SimpleXMLObject::TYPE_NAME);
        XMLObjectBuilder::deregisterBuilder(qname);
        XMLObjectBuilder::deregisterBuilder(qtype);
        delete m_resolver;
        delete m_trustEngine;
    }

    void testCerts() {
    
        vector<XSECCryptoX509*> certs;
        string pathname = data_path + "cert.pem";
        SecurityHelper::loadCertificatesFromFile(certs, pathname.c_str());
        pathname = data_path + "dsa-cert.pem";
        SecurityHelper::loadCertificatesFromFile(certs, pathname.c_str());
#ifdef XMLTOOLING_OPENSSL_HAVE_EC
        pathname = data_path + "ec-cert.pem";
        SecurityHelper::loadCertificatesFromFile(certs, pathname.c_str());
#endif

        for (vector<XSECCryptoX509*>::const_iterator cert=certs.begin(); cert!=certs.end(); ++cert) {
            // certs is ignore but must be present
            TSM_ASSERT("Trust Engine Validate", m_trustEngine->validate(*cert, certs, *m_resolver));
        }

        for_each(certs.begin(), certs.end(), xmltooling::cleanup<XSECCryptoX509>());
        certs.clear();

    }

};

