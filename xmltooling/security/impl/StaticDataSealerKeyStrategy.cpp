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

/**
 * URLEncoder.cpp
 * 
 * Interface to a URL-encoding mechanism along with a
 * default implementation. 
 */

#include "internal.h"
#include "security/DataSealer.h"
#include "util/XMLHelper.h"

#include <xercesc/util/Base64.hpp>

using namespace xmltooling;
using xercesc::Base64;
using xercesc::DOMElement;
using boost::scoped_ptr;
using namespace std;

namespace xmltooling {

    class XMLTOOL_DLLLOCAL StaticDataSealerKeyStrategy : public DataSealerKeyStrategy {
    public:
        StaticDataSealerKeyStrategy(const DOMElement* e);
        virtual ~StaticDataSealerKeyStrategy();

		Lockable* lock() { return this; }
		void unlock() {}

        pair<string,const XSECCryptoSymmetricKey*> getDefaultKey() const;
        const XSECCryptoSymmetricKey* getKey(const char* name) const;

    private:
        string m_name;
        scoped_ptr<XSECCryptoSymmetricKey> m_key;
    };

    DataSealerKeyStrategy* XMLTOOL_DLLLOCAL StaticDataSealerKeyStrategyFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new StaticDataSealerKeyStrategy(e);
    }
};

static const XMLCh key[] = UNICODE_LITERAL_3(k, e, y);
static const XMLCh name[] = UNICODE_LITERAL_4(n, a, m, e);

StaticDataSealerKeyStrategy::StaticDataSealerKeyStrategy(const DOMElement* e)
    : m_name(XMLHelper::getAttrString(e, "static", name))
{
    const XMLCh* encoded = e ? e->getAttributeNS(nullptr, key) : nullptr;
    if (encoded && *encoded) {
        XMLSize_t x;
        XMLByte* decoded = Base64::decodeToXMLByte(encoded, &x);
        if (!decoded)
            throw XMLSecurityException("Unable to decode base64-encoded key.");
        if (x >= 32) {
            m_key.reset(XSECPlatformUtils::g_cryptoProvider->keySymmetric(XSECCryptoSymmetricKey::KEY_AES_256));
        }
        else if (x >= 24) {
            m_key.reset(XSECPlatformUtils::g_cryptoProvider->keySymmetric(XSECCryptoSymmetricKey::KEY_AES_192));
        }
        else if (x >= 16) {
            m_key.reset(XSECPlatformUtils::g_cryptoProvider->keySymmetric(XSECCryptoSymmetricKey::KEY_AES_128));
        }
        else {
            XMLString::release((char**)&decoded);
            throw XMLSecurityException("Insufficient data to create 128-bit AES key.");
        }
        m_key->setKey(decoded, x);
        XMLString::release((char**)&decoded);
    }

    if (!m_key) {
        throw XMLSecurityException("No key attribute specified.");
    }
}

StaticDataSealerKeyStrategy::~StaticDataSealerKeyStrategy()
{
}

pair<string,const XSECCryptoSymmetricKey*> StaticDataSealerKeyStrategy::getDefaultKey() const
{
    return pair<string,const XSECCryptoSymmetricKey*>(m_name, m_key.get());
}

const XSECCryptoSymmetricKey * StaticDataSealerKeyStrategy::getKey(const char* name) const
{
    return name && m_name == name ? m_key.get() : nullptr;
}
