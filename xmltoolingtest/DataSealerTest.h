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

#include <xmltooling/exceptions.h>
#include <xmltooling/security/DataSealer.h>

#include <fstream>
#include <xercesc/util/Base64.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>

class DataSealerTest : public CxxTest::TestSuite {
public:
    void testStaticDataSealer() {
#ifdef XSEC_OPENSSL_HAVE_GCM
        unsigned char keybuf[32];
        TS_ASSERT_EQUALS(sizeof(keybuf), XSECPlatformUtils::g_cryptoProvider->getRandom(keybuf, sizeof(keybuf)));

        XMLSize_t x;
        XMLByte* encoded = Base64::encode(keybuf, sizeof(keybuf), &x);
        TS_ASSERT_LESS_THAN(0, x);
        auto_ptr_XMLCh widekey((char*)encoded);
        XMLString::release((char**)&encoded);

        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().newDocument();
        Janitor<DOMDocument> jdoc(doc);

        static const XMLCh _key[] = UNICODE_LITERAL_3(k,e,y);
        DOMElement* root = doc->createElementNS(nullptr, _key);
        root->setAttributeNS(nullptr, _key, widekey.get());
        doc->appendChild(root);

        auto_ptr<DataSealerKeyStrategy> keyStrategy(
            XMLToolingConfig::getConfig().DataSealerKeyStrategyManager.newPlugin(
                STATIC_DATA_SEALER_KEY_STRATEGY, doc->getDocumentElement(), false
                )
            );

		keyStrategy->lock();
        pair<string,const XSECCryptoSymmetricKey*> key = keyStrategy->getDefaultKey();
        TS_ASSERT_EQUALS("static", key.first);
        TSM_ASSERT_EQUALS("Wrong key type", key.second->getSymmetricKeyType(), XSECCryptoSymmetricKey::KEY_AES_256);
		keyStrategy->unlock();

        scoped_ptr<DataSealer> sealer(new DataSealer(keyStrategy.get()));
		keyStrategy.release();

        string data = "this is a test";

        string wrapped = sealer->wrap(data.c_str(), time(nullptr) + 500);
        string unwrapped = sealer->unwrap(wrapped.c_str());
            
        TSM_ASSERT_EQUALS("DataSealer output did not match.", data, unwrapped);

        wrapped = sealer->wrap(data.c_str(), time(nullptr) - 500);
        TSM_ASSERT_THROWS("DataSealer did not throw on expired data.", sealer->unwrap(wrapped.c_str()), IOException);

		wrapped = sealer->wrap(data.c_str(), time(nullptr) - 500);
		wrapped.insert(0, "invalid");
		TSM_ASSERT_THROWS("DataSealer did not throw on wrong key label.", sealer->unwrap(wrapped.c_str()), IOException);
#endif
    }

	void testVersionedDataSealer() {
#ifdef XSEC_OPENSSL_HAVE_GCM
		DOMDocument* doc = XMLToolingConfig::getConfig().getParser().newDocument();
		Janitor<DOMDocument> jdoc(doc);

		static const XMLCh _path[] = UNICODE_LITERAL_4(p, a, t, h);
		DOMElement* root = doc->createElementNS(nullptr, _path);
        string sealerpath = data_path + "sealer.keys";
		auto_ptr_XMLCh widepath(sealerpath.c_str());
		root->setAttributeNS(nullptr, _path, widepath.get());
		doc->appendChild(root);

		auto_ptr<DataSealerKeyStrategy> keyStrategy(
			XMLToolingConfig::getConfig().DataSealerKeyStrategyManager.newPlugin(
				VERSIONED_DATA_SEALER_KEY_STRATEGY, doc->getDocumentElement(), false
			)
		);

		keyStrategy->lock();
		
		pair<string, const XSECCryptoSymmetricKey*> key = keyStrategy->getDefaultKey();
		TS_ASSERT_EQUALS("4", key.first);
		TSM_ASSERT_EQUALS("Wrong key type", key.second->getSymmetricKeyType(), XSECCryptoSymmetricKey::KEY_AES_128);

		key.second = keyStrategy->getKey("1");
		TS_ASSERT(key.second != nullptr);
		TSM_ASSERT_EQUALS("Wrong key type", key.second->getSymmetricKeyType(), XSECCryptoSymmetricKey::KEY_AES_128);

		keyStrategy->unlock();

		scoped_ptr<DataSealer> sealer(new DataSealer(keyStrategy.get()));
		keyStrategy.release();

		string data = "this is a test";

		string wrapped = sealer->wrap(data.c_str(), time(nullptr) + 500);
		string unwrapped = sealer->unwrap(wrapped.c_str());

		TSM_ASSERT_EQUALS("DataSealer output did not match.", data, unwrapped);

		wrapped = sealer->wrap(data.c_str(), time(nullptr) - 500);
		TSM_ASSERT_THROWS("DataSealer did not throw on expired data.", sealer->unwrap(wrapped.c_str()), IOException);

		wrapped = sealer->wrap(data.c_str(), time(nullptr) - 500);
		wrapped.insert(0, "invalid");
		TSM_ASSERT_THROWS("DataSealer did not throw on wrong key label.", sealer->unwrap(wrapped.c_str()), IOException);
#endif
	}
};
