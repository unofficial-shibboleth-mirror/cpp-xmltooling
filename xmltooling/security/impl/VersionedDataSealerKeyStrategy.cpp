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
 * VersionedDataSealerKeyStrategy.cpp
 * 
 * DataSealerKeyStrategy based on a rolling key in a flat file.
 */

#include "internal.h"
#include "io/HTTPResponse.h"
#include "security/DataSealer.h"
#include "security/impl/ManagedResource.h"
#include "soap/HTTPSOAPTransport.h"
#include "util/PathResolver.h"
#include "util/NDC.h"
#include "util/XMLHelper.h"

#include <map>
#include <fstream>
#include <boost/shared_ptr.hpp>
#include <xercesc/util/Base64.hpp>

using namespace xmltooling::logging;
using namespace xmltooling;
using xercesc::Base64;
using xercesc::DOMElement;
using boost::scoped_ptr;
using namespace std;

namespace xmltooling {

    class XMLTOOL_DLLLOCAL VersionedDataSealerKeyStrategy : public DataSealerKeyStrategy, public ManagedResource {
    public:
        VersionedDataSealerKeyStrategy(const DOMElement* e, bool deprecationSupport=true);
        virtual ~VersionedDataSealerKeyStrategy();

        Lockable* lock();
        void unlock() {
            m_lock->unlock();
        }

        pair<string,const XSECCryptoSymmetricKey*> getDefaultKey() const;
        const XSECCryptoSymmetricKey* getKey(const char* name) const;

    private:
        void load();
        void load(ifstream& in);

            Category& m_log;
        scoped_ptr<RWLock> m_lock;
        mutable map< string, boost::shared_ptr<XSECCryptoSymmetricKey> > m_keyMap;
        string m_default;
    };

    DataSealerKeyStrategy* XMLTOOL_DLLLOCAL VersionedDataSealerKeyStrategyFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new VersionedDataSealerKeyStrategy(e, deprecationSupport);
    }

};

VersionedDataSealerKeyStrategy::VersionedDataSealerKeyStrategy(const DOMElement* e, bool deprecationSupport)
    : m_log(Category::getInstance(XMLTOOLING_LOGCAT".DataSealer")), m_lock(RWLock::create())
{
    static const XMLCh backingFilePath[] = UNICODE_LITERAL_15(b,a,c,k,i,n,g,F,i,l,e,P,a,t,h);
    static const XMLCh path[] = UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh _reloadChanges[] = UNICODE_LITERAL_13(r,e,l,o,a,d,C,h,a,n,g,e,s);
    static const XMLCh _reloadInterval[] = UNICODE_LITERAL_14(r,e,l,o,a,d,I,n,t,e,r,v,a,l);
    static const XMLCh url[] = UNICODE_LITERAL_3(u,r,l);

    if (e->hasAttributeNS(nullptr, path)) {
        source = XMLHelper::getAttrString(e, nullptr, path);
        XMLToolingConfig::getConfig().getPathResolver()->resolve(source, PathResolver::XMLTOOLING_CFG_FILE);
        local = true;
        reloadChanges = XMLHelper::getAttrBool(e, true, _reloadChanges);
    }
    else if (e->hasAttributeNS(nullptr, url)) {
        source = XMLHelper::getAttrString(e, nullptr, url);
        local = false;
        backing = XMLHelper::getAttrString(e, nullptr, backingFilePath);
        if (backing.empty())
            throw XMLSecurityException("DataSealer can't support remote resource, backingFilePath missing.");
        XMLToolingConfig::getConfig().getPathResolver()->resolve(backing, PathResolver::XMLTOOLING_CACHE_FILE);
        reloadInterval = XMLHelper::getAttrInt(e, 0, _reloadInterval);
    }
    else {
        throw XMLSecurityException("DataSealer requires path or url XML attribute.");
    }

    m_deprecationSupport = deprecationSupport;
}

VersionedDataSealerKeyStrategy::~VersionedDataSealerKeyStrategy()
{
}

void VersionedDataSealerKeyStrategy::load()
{
    if (source.empty())
        return;
    m_log.info("loading secret keys from %s (%s)", local ? "local file" : "URL", source.c_str());
    if (local) {
        ifstream in(source.c_str());
        load(in);
    }
    else {
        scoped_ptr<SOAPTransport> t(getTransport());

        // Fetch the data.
        t->send();
        istream& msg = t->receive();

        // Check for "not modified" status.
        if (dynamic_cast<HTTPSOAPTransport*>(t.get()) && t->getStatusCode() == HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED)
            throw (long)HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED;

        // Dump to output file.
        ofstream out(backing.c_str(), fstream::trunc | fstream::binary);
        out << msg.rdbuf();
        out.close();

        ifstream in(backing.c_str());
        load(in);
    }
}

void VersionedDataSealerKeyStrategy::load(ifstream& in)
{
    m_default.clear();
    m_keyMap.clear();
    
    string line;
    while (getline(in, line).good()) {
        size_t delim = line.find(':');
        if (delim != string::npos && delim > 0) {
            string name = line.substr(0, delim);

            XMLSize_t x;
            XMLByte* decoded = Base64::decode((const XMLByte*) line.c_str() + delim + 1, &x);
            if (!decoded) {
                m_log.warn("failed to base64-decode key (%s)", name.c_str());
                continue;
            }
            boost::shared_ptr<XSECCryptoSymmetricKey> key;
            if (x >= 32) {
                key.reset(XSECPlatformUtils::g_cryptoProvider->keySymmetric(XSECCryptoSymmetricKey::KEY_AES_256));
            }
            else if (x >= 24) {
                key.reset(XSECPlatformUtils::g_cryptoProvider->keySymmetric(XSECCryptoSymmetricKey::KEY_AES_192));
            }
            else if (x >= 16) {
                key.reset(XSECPlatformUtils::g_cryptoProvider->keySymmetric(XSECCryptoSymmetricKey::KEY_AES_128));
            }
            else {
                XMLString::release((char**)&decoded);
                m_log.warn("insufficient data to create 128-bit AES key (%s)", name.c_str());
                continue;
            }
            key->setKey(decoded, x);
            XMLString::release((char**)&decoded);

            m_default = name;
            m_keyMap[name] = key;
            m_log.debug("loaded secret key (%s)", name.c_str());
        }
    }
}

Lockable* VersionedDataSealerKeyStrategy::lock()
{
#ifdef _DEBUG
    NDC ndc("lock");
#endif
    m_lock->rdlock();

    // Check our managed resource while holding a read lock for staleness.
    // If it comes back false, the lock is left as is, and the resource was stable.
    // If it comes back true, the lock was elevated to a write lock, and the resource
    // needs to be reloaded, and the keys updated.

    bool writelock = false;

    if (stale(m_log, m_lock.get())) {
        writelock = true;
        try {
            load();
        }
        catch (long& ex) {
            if (ex == HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED) {
                m_log.info("remote key source (%s) unchanged from cached version", source.c_str());
            }
            else {
                // Shouldn't happen, we should only get codes intended to be gracefully handled.
                m_log.crit("maintaining existing keys, remote fetch returned atypical status code (%d)", ex);
            }
        }
        catch (const exception& ex) {
            m_log.crit("maintaining existing keys: %s", ex.what());
        }
    }

    if (writelock) {
        m_lock->unlock();
        m_lock->rdlock();
    }
    return this;

}

pair<string,const XSECCryptoSymmetricKey*> VersionedDataSealerKeyStrategy::getDefaultKey() const
{
    const XSECCryptoSymmetricKey* key = m_keyMap[m_default].get();
    if (!key)
        throw XMLSecurityException("Unable to find default key.");
    return make_pair(m_default, key);
}

const XSECCryptoSymmetricKey* VersionedDataSealerKeyStrategy::getKey(const char* name) const
{
    return m_keyMap[name].get();
}
