/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * PKIXTrustEngine.cpp
 * 
 * Shibboleth-specific PKIX-validation TrustEngine
 */

#include "internal.h"

#include "logging.h"
#include "XMLToolingConfig.h"
#include "security/AbstractPKIXTrustEngine.h"
#include "security/CredentialResolver.h"
#include "security/X509Credential.h"
#include "util/XMLHelper.h"

#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmlsignature;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace xmltooling {

    static const XMLCh _CredentialResolver[] =  UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
    static const XMLCh type[] =                 UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh certificate[] =          UNICODE_LITERAL_11(c,e,r,t,i,f,i,c,a,t,e);
    static const XMLCh Certificate[] =          UNICODE_LITERAL_11(C,e,r,t,i,f,i,c,a,t,e);
    static const XMLCh Path[] =                 UNICODE_LITERAL_4(P,a,t,h);
    static const XMLCh verifyDepth[] =          UNICODE_LITERAL_11(v,e,r,i,f,y,D,e,p,t,h);

    class XMLTOOL_DLLLOCAL StaticPKIXTrustEngine : public AbstractPKIXTrustEngine
    {
    public:
        StaticPKIXTrustEngine(const DOMElement* e=NULL);

        virtual ~StaticPKIXTrustEngine() {
            if (m_credResolver) {
                m_credResolver->unlock();
                delete m_credResolver;
            }
        }
        
        AbstractPKIXTrustEngine::PKIXValidationInfoIterator* getPKIXValidationInfoIterator(
            const CredentialResolver& pkixSource, CredentialCriteria* criteria=NULL
            ) const;

        const KeyInfoResolver* getKeyInfoResolver() const {
            return m_keyInfoResolver ? m_keyInfoResolver : XMLToolingConfig::getConfig().getKeyInfoResolver();
        }

    private:
        CredentialResolver* m_credResolver;
        int m_depth;
        vector<XSECCryptoX509*> m_certs;
        vector<XSECCryptoX509CRL*> m_crls;
        friend class XMLTOOL_DLLLOCAL StaticPKIXIterator;
    };
    
    TrustEngine* XMLTOOL_DLLLOCAL StaticPKIXTrustEngineFactory(const DOMElement* const & e)
    {
        return new StaticPKIXTrustEngine(e);
    }

    class XMLTOOL_DLLLOCAL StaticPKIXIterator : public AbstractPKIXTrustEngine::PKIXValidationInfoIterator
    {
    public:
        StaticPKIXIterator(const StaticPKIXTrustEngine& engine) : m_engine(engine), m_done(false) {
        }

        virtual ~StaticPKIXIterator() {
        }

        bool next() {
            if (m_done)
                return false;
            m_done = true;
            return true;
        }

        int getVerificationDepth() const {
            return m_engine.m_depth;
        }
        
        const vector<XSECCryptoX509*>& getTrustAnchors() const {
            return m_engine.m_certs;
        }

        const vector<XSECCryptoX509CRL*>& getCRLs() const {
            return m_engine.m_crls;
        }
    
    private:
        const StaticPKIXTrustEngine& m_engine;
        bool m_done;
    };
};

StaticPKIXTrustEngine::StaticPKIXTrustEngine(const DOMElement* e) : AbstractPKIXTrustEngine(e)
{
    const XMLCh* depth = e ? e->getAttributeNS(NULL, verifyDepth) : NULL;
    if (depth && *depth)
        m_depth = XMLString::parseInt(depth);
    else
        m_depth = 1;

    if (e && e->hasAttributeNS(NULL,certificate)) {
        // Simple File resolver config rooted here.
        m_credResolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(FILESYSTEM_CREDENTIAL_RESOLVER,e);
    }
    else {
        e = e ? XMLHelper::getFirstChildElement(e, _CredentialResolver) : NULL;
        auto_ptr_char t(e ? e->getAttributeNS(NULL,type) : NULL);
        if (t.get()) {
            m_credResolver = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(t.get(),e);
        }
        else
            throw XMLSecurityException("Missing <CredentialResolver> element, or no type attribute found");
    }

    m_credResolver->lock();

    // Merge together all X509Credentials we can resolve.
    try {
        vector<const Credential*> creds;
        m_credResolver->resolve(creds);
        for (vector<const Credential*>::const_iterator i = creds.begin(); i != creds.end(); ++i) {
            const X509Credential* xcred = dynamic_cast<const X509Credential*>(*i);
            if (xcred) {
                m_certs.insert(m_certs.end(), xcred->getEntityCertificateChain().begin(), xcred->getEntityCertificateChain().end());
                if (xcred->getCRL())
                    m_crls.push_back(xcred->getCRL());
            }
        }
    }
    catch (exception& ex) {
        logging::Category::getInstance(XMLTOOLING_LOGCAT".TrustEngine.StaticPKIX").error(ex.what());
    }
}

AbstractPKIXTrustEngine::PKIXValidationInfoIterator* StaticPKIXTrustEngine::getPKIXValidationInfoIterator(
    const CredentialResolver& pkixSource, CredentialCriteria* criteria
    ) const
{
    return new StaticPKIXIterator(*this);
}
