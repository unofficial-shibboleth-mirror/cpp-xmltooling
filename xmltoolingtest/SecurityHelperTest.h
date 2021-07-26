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

#include <xmltooling/security/SecurityHelper.h>

#include <xsec/enc/XSECCryptoKey.hpp>
#include <xsec/enc/XSECCryptoX509.hpp>

class SecurityHelperTest : public CxxTest::TestSuite {
    vector<XSECCryptoX509*> certs;

    SOAPTransport* getTransport(const char* url) {
        SOAPTransport::Address addr("SecurityHelperTest", "spaces.internet2.edu", url);
        string scheme(addr.m_endpoint, strchr(addr.m_endpoint,':') - addr.m_endpoint);
        return XMLToolingConfig::getConfig().SOAPTransportManager.newPlugin(scheme.c_str(), addr, false);
    }

    void skipNetworked() {
        if (getenv("XMLTOOLINGTEST_SKIP_NETWORKED")) {
#ifdef TS_SKIP
            TS_SKIP("requires network access");
#endif
        }
    }

public:
    void setUp() {
    }

    void tearDown() {
        for_each(certs.begin(), certs.end(), xmltooling::cleanup<XSECCryptoX509>());
        certs.clear();
    }

    void testKeysFromFiles() {
        string pathname = data_path + "key.pem";
        scoped_ptr<XSECCryptoKey> key1(SecurityHelper::loadKeyFromFile(pathname.c_str()));
        pathname = data_path + "key.der";
        scoped_ptr<XSECCryptoKey> key2(SecurityHelper::loadKeyFromFile(pathname.c_str()));
        pathname = data_path + "test.pfx";
        scoped_ptr<XSECCryptoKey> key3(SecurityHelper::loadKeyFromFile(pathname.c_str(), nullptr, "password"));

        TSM_ASSERT("PEM/DER keys did not match", SecurityHelper::matches(*key1.get(), *key2.get()));
        TSM_ASSERT("DER/PKCS12 keys did not match", SecurityHelper::matches(*key2.get(), *key3.get()));

        pathname = data_path + "key2.pem";
        scoped_ptr<XSECCryptoKey> key4(SecurityHelper::loadKeyFromFile(pathname.c_str()));
        TSM_ASSERT("Different keys matched", !SecurityHelper::matches(*key3.get(), *key4.get()));
    }

    void testKeysFromURLs() {
        skipNetworked();
        string pathname = data_path + "key.pem.bak";
        scoped_ptr<SOAPTransport> t1(getTransport("https://test.shibboleth.net/git/view/?p=cpp-xmltooling.git&a=blob_plain&hb=HEAD&f=xmltoolingtest/data/key.pem"));
        scoped_ptr<XSECCryptoKey> key1(SecurityHelper::loadKeyFromURL(*t1.get(), pathname.c_str()));
        pathname = data_path + "key.der.bak";
        scoped_ptr<SOAPTransport> t2(getTransport("https://test.shibboleth.net/git/view/?p=cpp-xmltooling.git&a=blob_plain&hb=HEAD&f=xmltoolingtest/data/key.der"));
        scoped_ptr<XSECCryptoKey> key2(SecurityHelper::loadKeyFromURL(*t2.get(), pathname.c_str()));
        pathname = data_path + "test.pfx.bak";
        scoped_ptr<SOAPTransport> t3(getTransport("https://test.shibboleth.net/git/view/?p=cpp-xmltooling.git&a=blob_plain&hb=HEAD&f=xmltoolingtest/data/test.pfx"));
        scoped_ptr<XSECCryptoKey> key3(SecurityHelper::loadKeyFromURL(*t3.get(), pathname.c_str(), nullptr, "password"));

        TSM_ASSERT("PEM/DER keys did not match", SecurityHelper::matches(*key1.get(), *key2.get()));
        TSM_ASSERT("DER/PKCS12 keys did not match", SecurityHelper::matches(*key2.get(), *key3.get()));
    }

    void testCertificatesFromFiles() {
        string pathname = data_path + "cert.pem";
        SecurityHelper::loadCertificatesFromFile(certs, pathname.c_str());
        pathname = data_path + "cert.der";
        SecurityHelper::loadCertificatesFromFile(certs, pathname.c_str());
        pathname = data_path + "test.pfx";
        SecurityHelper::loadCertificatesFromFile(certs, pathname.c_str(), nullptr, "password");

        TSM_ASSERT_EQUALS("Wrong certificate count", certs.size(), 3);

        scoped_ptr<XSECCryptoKey> key1(certs[0]->clonePublicKey());
        scoped_ptr<XSECCryptoKey> key2(certs[1]->clonePublicKey());
        scoped_ptr<XSECCryptoKey> key3(certs[2]->clonePublicKey());

        TSM_ASSERT("PEM/DER keys did not match", SecurityHelper::matches(*key1.get(), *key2.get()));
        TSM_ASSERT("DER/PKCS12 keys did not match", SecurityHelper::matches(*key2.get(), *key3.get()));

        TSM_ASSERT_EQUALS(
            "Certificate and its key produced different DER encodings",
            SecurityHelper::getDEREncoding(*certs[2], nullptr), SecurityHelper::getDEREncoding(*key1.get(), nullptr)
            );

        TSM_ASSERT_EQUALS(
            "Certificate and its key produced different hashed encodings",
            SecurityHelper::getDEREncoding(*certs[2], "SHA1"), SecurityHelper::getDEREncoding(*key1.get(), "SHA1")
            );

        TSM_ASSERT_EQUALS(
            "Certificate and its key produced different hashed encodings",
            SecurityHelper::getDEREncoding(*certs[2], "SHA256"), SecurityHelper::getDEREncoding(*key1.get(), "SHA256")
            );

        for_each(certs.begin(), certs.end(), xmltooling::cleanup<XSECCryptoX509>());
        certs.clear();
    }

    void testCertificatesFromURLs() {
        skipNetworked();
        string pathname = data_path + "cert.pem.bak";
        scoped_ptr<SOAPTransport> t1(getTransport("https://test.shibboleth.net/git/view/?p=cpp-xmltooling.git&a=blob_plain&hb=HEAD&f=xmltoolingtest/data/cert.pem"));
        SecurityHelper::loadCertificatesFromURL(certs, *t1.get(), pathname.c_str());
        pathname = data_path + "cert.der.bak";
        scoped_ptr<SOAPTransport> t2(getTransport("https://test.shibboleth.net/git/view/?p=cpp-xmltooling.git&a=blob_plain&hb=HEAD&f=xmltoolingtest/data/cert.der"));
        SecurityHelper::loadCertificatesFromURL(certs, *t2.get(), pathname.c_str());
        pathname = data_path + "test.pfx.bak";
        scoped_ptr<SOAPTransport> t3(getTransport("https://test.shibboleth.net/git/view/?p=cpp-xmltooling.git&a=blob_plain&hb=HEAD&f=xmltoolingtest/data/test.pfx"));
        SecurityHelper::loadCertificatesFromURL(certs, *t3.get(), pathname.c_str(), nullptr, "password");

        TSM_ASSERT_EQUALS("Wrong certificate count", certs.size(), 3);

        scoped_ptr<XSECCryptoKey> key1(certs[0]->clonePublicKey());
        scoped_ptr<XSECCryptoKey> key2(certs[0]->clonePublicKey());
        scoped_ptr<XSECCryptoKey> key3(certs[0]->clonePublicKey());

        TSM_ASSERT("PEM/DER keys did not match", SecurityHelper::matches(*key1.get(), *key2.get()));
        TSM_ASSERT("DER/PKCS12 keys did not match", SecurityHelper::matches(*key2.get(), *key3.get()));

        for_each(certs.begin(), certs.end(), xmltooling::cleanup<XSECCryptoX509>());
        certs.clear();
    }
};
