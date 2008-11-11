/*
 *  Copyright 2001-2008 Internet2
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
 * FilesystemCredentialResolver.cpp
 *
 * Supplies credentials from local files
 */

#include "internal.h"
#include "logging.h"
#include "security/BasicX509Credential.h"
#include "security/CredentialCriteria.h"
#include "security/CredentialResolver.h"
#include "security/KeyInfoResolver.h"
#include "security/OpenSSLCredential.h"
#include "security/SecurityHelper.h"
#include "util/NDC.h"
#include "util/PathResolver.h"
#include "util/XMLHelper.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/pkcs12.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace xmltooling {

    // The ManagedResource classes handle memory management, loading of the files
    // and staleness detection. A copy of the active objects is always stored in
    // these instances.

    class XMLTOOL_DLLLOCAL ManagedResource {
    protected:
        ManagedResource() : local(true), reloadChanges(true), filestamp(0), reloadInterval(0) {}
        ~ManagedResource() {}

        SOAPTransport* getTransport() {
            SOAPTransport::Address addr("FilesystemCredentialResolver", source.c_str(), source.c_str());
            string scheme(addr.m_endpoint, strchr(addr.m_endpoint,':') - addr.m_endpoint);
            return XMLToolingConfig::getConfig().SOAPTransportManager.newPlugin(scheme.c_str(), addr);
        }

    public:
        bool stale(Category& log, RWLock* lock=NULL) {
            if (local) {
#ifdef WIN32
                struct _stat stat_buf;
                if (_stat(source.c_str(), &stat_buf) != 0)
                    return false;
#else
                struct stat stat_buf;
                if (stat(source.c_str(), &stat_buf) != 0)
                    return false;
#endif
                if (filestamp >= stat_buf.st_mtime)
                    return false;

                // If necessary, elevate lock and recheck.
                if (lock) {
                    log.debug("timestamp of local resource changed, elevating to a write lock");
                    lock->unlock();
                    lock->wrlock();
                    if (filestamp >= stat_buf.st_mtime) {
                        // Somebody else handled it, just downgrade.
                        log.debug("update of local resource handled by another thread, downgrading lock");
                        lock->unlock();
                        lock->rdlock();
                        return false;
                    }
                }

                // Update the timestamp regardless. No point in repeatedly trying.
                filestamp = stat_buf.st_mtime;
                log.info("change detected, reloading local resource...");
            }
            else {
                time_t now = time(NULL);

                // Time to reload?
                if (now - filestamp < reloadInterval)
                    return false;

                // If necessary, elevate lock and recheck.
                if (lock) {
                    log.debug("reload interval for remote resource elapsed, elevating to a write lock");
                    lock->unlock();
                    lock->wrlock();
                    if (now - filestamp < reloadInterval) {
                        // Somebody else handled it, just downgrade.
                        log.debug("update of remote resource handled by another thread, downgrading lock");
                        lock->unlock();
                        lock->rdlock();
                        return false;
                    }
                }

                filestamp = now;
                log.info("reloading remote resource...");
            }
            return true;
        }

        bool local,reloadChanges;
        string format,source,backing;
        time_t filestamp,reloadInterval;
    };

    class XMLTOOL_DLLLOCAL ManagedKey : public ManagedResource {
    public:
        ManagedKey() : key(NULL) {}
        ~ManagedKey() { delete key; }
        void load(Category& log, const char* password) {
            if (source.empty())
                return;
            XSECCryptoKey* nkey=NULL;
            if (local) {
                nkey = SecurityHelper::loadKeyFromFile(source.c_str(), format.c_str(), password);
            }
            else {
                auto_ptr<SOAPTransport> t(getTransport());
                log.info("loading private key from URL (%s)", source.c_str());
                nkey = SecurityHelper::loadKeyFromURL(*t.get(), backing.c_str(), format.c_str(), password);
            }
            delete key;
            key = nkey;
            if (format.empty())
                format = SecurityHelper::guessEncodingFormat(local ? source.c_str() : backing.c_str());
        }

        XSECCryptoKey* key;
    };

    class XMLTOOL_DLLLOCAL ManagedCert : public ManagedResource {
    public:
        ManagedCert() {}
        ~ManagedCert() { for_each(certs.begin(), certs.end(), xmltooling::cleanup<XSECCryptoX509>()); }
        void load(Category& log, const char* password) {
            if (source.empty())
                return;
            vector<XSECCryptoX509*> ncerts;
            if (local) {
                SecurityHelper::loadCertificatesFromFile(ncerts, source.c_str(), format.c_str(), password);
            }
            else {
                auto_ptr<SOAPTransport> t(getTransport());
                log.info("loading certificate(s) from URL (%s)", source.c_str());
                SecurityHelper::loadCertificatesFromURL(ncerts, *t.get(), backing.c_str(), format.c_str(), password);
            }
            for_each(certs.begin(), certs.end(), xmltooling::cleanup<XSECCryptoX509>());
            certs = ncerts;
            if (format.empty())
                format = SecurityHelper::guessEncodingFormat(local ? source.c_str() : backing.c_str());
        }
        vector<XSECCryptoX509*> certs;
    };

    class XMLTOOL_DLLLOCAL ManagedCRL : public ManagedResource {
    public:
        ManagedCRL() {}
        ~ManagedCRL() { for_each(crls.begin(), crls.end(), xmltooling::cleanup<XSECCryptoX509CRL>()); }
        void load(Category& log) {
            if (source.empty())
                return;
            vector<XSECCryptoX509CRL*> ncrls;
            if (local) {
                SecurityHelper::loadCRLsFromFile(ncrls, source.c_str(), format.c_str());
            }
            else {
                auto_ptr<SOAPTransport> t(getTransport());
                log.info("loading CRL(s) from URL (%s)", source.c_str());
                SecurityHelper::loadCRLsFromURL(ncrls, *t.get(), backing.c_str(), format.c_str());
            }
            for_each(crls.begin(), crls.end(), xmltooling::cleanup<XSECCryptoX509CRL>());
            crls = ncrls;
            if (format.empty())
                format = SecurityHelper::guessEncodingFormat(local ? source.c_str() : backing.c_str());
        }
        vector<XSECCryptoX509CRL*> crls;
    };

    class XMLTOOL_DLLLOCAL FilesystemCredential;
    class XMLTOOL_DLLLOCAL FilesystemCredentialResolver : public CredentialResolver
    {
        friend class XMLTOOL_DLLLOCAL FilesystemCredential;
    public:
        FilesystemCredentialResolver(const DOMElement* e);
        virtual ~FilesystemCredentialResolver();

        Lockable* lock();
        void unlock() {
            m_lock->unlock();
        }

        const Credential* resolve(const CredentialCriteria* criteria=NULL) const;

        virtual vector<const Credential*>::size_type resolve(
            vector<const Credential*>& results, const CredentialCriteria* criteria=NULL
            ) const;

    private:
        Credential* getCredential();

        RWLock* m_lock;
        Credential* m_credential;
        string m_keypass,m_certpass;
        unsigned int m_keyinfomask,m_usage;
        vector<string> m_keynames;

        ManagedKey m_key;
        vector<ManagedCert> m_certs;
        vector<ManagedCRL> m_crls;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLTOOL_DLLLOCAL FilesystemCredential : public OpenSSLCredential, public BasicX509Credential
    {
    public:
        FilesystemCredential(
            FilesystemCredentialResolver* resolver, XSECCryptoKey* key, const vector<XSECCryptoX509*>& xseccerts, const vector<XSECCryptoX509CRL*>& crls
            ) : BasicX509Credential(key ? key : (xseccerts.empty() ? NULL : xseccerts.front()->clonePublicKey()), xseccerts, crls), m_resolver(resolver) {
            extract();
            m_keyNames.insert(m_resolver->m_keynames.begin(), m_resolver->m_keynames.end());
        }

        virtual ~FilesystemCredential() {
        }

        unsigned int getUsage() const {
            return m_resolver->m_usage;
        }

        void initKeyInfo(unsigned int types=0) {
            BasicX509Credential::initKeyInfo(types);
        }

        void attach(SSL_CTX* ctx) const;

    private:
        FilesystemCredentialResolver* m_resolver;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    CredentialResolver* XMLTOOL_DLLLOCAL FilesystemCredentialResolverFactory(const DOMElement* const & e)
    {
        return new FilesystemCredentialResolver(e);
    }

    static const XMLCh backingFilePath[] =  UNICODE_LITERAL_15(b,a,c,k,i,n,g,F,i,l,e,P,a,t,h);
    static const XMLCh _CredentialResolver[] = UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
    static const XMLCh CAPath[] =           UNICODE_LITERAL_6(C,A,P,a,t,h);
    static const XMLCh Certificate[] =      UNICODE_LITERAL_11(C,e,r,t,i,f,i,c,a,t,e);
    static const XMLCh _certificate[] =     UNICODE_LITERAL_11(c,e,r,t,i,f,i,c,a,t,e);
    static const XMLCh CRL[] =              UNICODE_LITERAL_3(C,R,L);
    static const XMLCh _format[] =          UNICODE_LITERAL_6(f,o,r,m,a,t);
    static const XMLCh Key[] =              UNICODE_LITERAL_3(K,e,y);
    static const XMLCh _key[] =             UNICODE_LITERAL_3(k,e,y);
    static const XMLCh keyInfoMask[] =      UNICODE_LITERAL_11(k,e,y,I,n,f,o,M,a,s,k);
    static const XMLCh keyName[] =          UNICODE_LITERAL_7(k,e,y,N,a,m,e);
    static const XMLCh Name[] =             UNICODE_LITERAL_4(N,a,m,e);
    static const XMLCh password[] =         UNICODE_LITERAL_8(p,a,s,s,w,o,r,d);
    static const XMLCh Path[] =             UNICODE_LITERAL_4(P,a,t,h);
    static const XMLCh _reloadChanges[] =   UNICODE_LITERAL_13(r,e,l,o,a,d,C,h,a,n,g,e,s);
    static const XMLCh _reloadInterval[] =  UNICODE_LITERAL_14(r,e,l,o,a,d,I,n,t,e,r,v,a,l);
    static const XMLCh _URL[] =             UNICODE_LITERAL_3(U,R,L);
    static const XMLCh _use[] =             UNICODE_LITERAL_3(u,s,e);
};

FilesystemCredentialResolver::FilesystemCredentialResolver(const DOMElement* e)
    : m_lock(NULL), m_credential(NULL), m_usage(Credential::UNSPECIFIED_CREDENTIAL)
{
#ifdef _DEBUG
    NDC ndc("FilesystemCredentialResolver");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT".CredentialResolver."FILESYSTEM_CREDENTIAL_RESOLVER);

    // Default to disable X509IssuerSerial due to schema validation issues.
    m_keyinfomask =
        Credential::KEYINFO_KEY_NAME |
        Credential::KEYINFO_KEY_VALUE |
        X509Credential::KEYINFO_X509_CERTIFICATE |
        X509Credential::KEYINFO_X509_SUBJECTNAME;
    if (e && e->hasAttributeNS(NULL,keyInfoMask))
        m_keyinfomask = XMLString::parseInt(e->getAttributeNS(NULL,keyInfoMask));

    if (e && (e->hasAttributeNS(NULL,_certificate) || e->hasAttributeNS(NULL,_key))) {
        // Dummy up a simple file resolver config using these attributes.
        DOMElement* dummy = e->getOwnerDocument()->createElementNS(NULL,_CredentialResolver);
        DOMElement* child;
        DOMElement* path;
        if (e->hasAttributeNS(NULL,_key)) {
            child = e->getOwnerDocument()->createElementNS(NULL,Key);
            dummy->appendChild(child);
            path = e->getOwnerDocument()->createElementNS(NULL,Path);
            child->appendChild(path);
            path->appendChild(e->getOwnerDocument()->createTextNode(e->getAttributeNS(NULL,_key)));
            if (e->hasAttributeNS(NULL,password))
                child->setAttributeNS(NULL,password,e->getAttributeNS(NULL,password));
            if (e->hasAttributeNS(NULL,keyName)) {
                path = e->getOwnerDocument()->createElementNS(NULL,Name);
                child->appendChild(path);
                path->appendChild(e->getOwnerDocument()->createTextNode(e->getAttributeNS(NULL,keyName)));
            }
        }
        if (e->hasAttributeNS(NULL,_certificate)) {
            child = e->getOwnerDocument()->createElementNS(NULL,Certificate);
            dummy->appendChild(child);
            path = e->getOwnerDocument()->createElementNS(NULL,Path);
            child->appendChild(path);
            path->appendChild(e->getOwnerDocument()->createTextNode(e->getAttributeNS(NULL,_certificate)));
        }
        e = dummy;  // reset "root" to the dummy config element
    }

    const XMLCh* prop;
    const DOMElement* root = e;

    // Save off usage flags.
    const XMLCh* usage = root->getAttributeNS(NULL,_use);
    if (usage && *usage) {
        auto_ptr_char u(usage);
        if (!strcmp(u.get(), "signing"))
            m_usage = Credential::SIGNING_CREDENTIAL | Credential::TLS_CREDENTIAL;
        else if (!strcmp(u.get(), "TLS"))
            m_usage = Credential::TLS_CREDENTIAL;
        else if (!strcmp(u.get(), "encryption"))
            m_usage = Credential::ENCRYPTION_CREDENTIAL;
    }

    // Move to Key.
    const DOMElement* keynode = XMLHelper::getFirstChildElement(root,Key);
    if (keynode) {
        prop = keynode->getAttributeNS(NULL,_format);
        if (prop && *prop) {
            auto_ptr_char f(prop);
            m_key.format = f.get();
        }

        prop = keynode->getAttributeNS(NULL,password);
        if (prop && *prop) {
            auto_ptr_char kp(prop);
            m_keypass = kp.get();
        }

        if ((e=XMLHelper::getFirstChildElement(keynode,Path)) && e->hasChildNodes()) {
            prop = e->getFirstChild()->getNodeValue();
            auto_ptr_char kpath(prop);
            m_key.source = kpath.get();
            XMLToolingConfig::getConfig().getPathResolver()->resolve(m_key.source, PathResolver::XMLTOOLING_CFG_FILE);
            m_key.local = true;
            prop = e->getAttributeNS(NULL,_reloadChanges);
            if (prop && (*prop==chLatin_f) || (*prop==chDigit_0))
                m_key.reloadChanges = false;
        }
        else if ((e=XMLHelper::getFirstChildElement(keynode,_URL)) && e->hasChildNodes()) {
            prop = e->getFirstChild()->getNodeValue();
            auto_ptr_char kpath(prop);
            m_key.source = kpath.get();
            m_key.local = false;
            prop = e->getAttributeNS(NULL,backingFilePath);
            if (!prop || !*prop)
                throw XMLSecurityException("FilesystemCredentialResolver can't access key, backingFilePath missing from URL element.");
            auto_ptr_char b(prop);
            m_key.backing = b.get();
            XMLToolingConfig::getConfig().getPathResolver()->resolve(m_key.backing, PathResolver::XMLTOOLING_RUN_FILE);
            prop = e->getAttributeNS(NULL,_reloadInterval);
            if (prop && *prop)
                m_key.reloadInterval = XMLString::parseInt(prop);
        }
        else {
            log.error("Path/URL element missing inside Key element");
            throw XMLSecurityException("FilesystemCredentialResolver can't access key, no Path or URL element specified.");
        }

        e = XMLHelper::getFirstChildElement(keynode, Name);
        while (e) {
            if (e->hasChildNodes()) {
                auto_ptr_char n(e->getFirstChild()->getNodeValue());
                if (n.get() && *n.get())
                    m_keynames.push_back(n.get());
            }
            e = XMLHelper::getNextSiblingElement(e, Name);
        }
    }

    // Check for CRL.
    const DOMElement* crlnode = XMLHelper::getFirstChildElement(root,CRL);
    if (crlnode) {
        const XMLCh* crlformat = crlnode->getAttributeNS(NULL,_format);
        e = XMLHelper::getFirstChildElement(crlnode,Path);
        while (e) {
            if (e->hasChildNodes()) {
                m_crls.push_back(ManagedCRL());
                ManagedResource& crl = m_crls.back();
                if (crlformat && *crlformat) {
                    auto_ptr_char f(crlformat);
                    crl.format = f.get();
                }
                prop = e->getFirstChild()->getNodeValue();
                auto_ptr_char crlpath(prop);
                crl.source = crlpath.get();
                XMLToolingConfig::getConfig().getPathResolver()->resolve(crl.source, PathResolver::XMLTOOLING_CFG_FILE);
                crl.local = true;
                prop = e->getAttributeNS(NULL,_reloadChanges);
                if (prop && (*prop==chLatin_f) || (*prop==chDigit_0))
                    crl.reloadChanges = false;
            }
            e = XMLHelper::getNextSiblingElement(e,Path);
        }

        e=XMLHelper::getFirstChildElement(crlnode,_URL);
        while (e) {
            if (e->hasChildNodes()) {
                m_crls.push_back(ManagedCRL());
                ManagedResource& crl = m_crls.back();
                if (crlformat && *crlformat) {
                    auto_ptr_char f(crlformat);
                    crl.format = f.get();
                }
                prop = e->getFirstChild()->getNodeValue();
                auto_ptr_char crlpath(prop);
                crl.source = crlpath.get();
                crl.local = false;
                prop = e->getAttributeNS(NULL,backingFilePath);
                if (!prop || !*prop)
                    throw XMLSecurityException("FilesystemCredentialResolver can't access CRL, backingFilePath missing from URL element.");
                auto_ptr_char b(prop);
                crl.backing = b.get();
                XMLToolingConfig::getConfig().getPathResolver()->resolve(crl.backing, PathResolver::XMLTOOLING_RUN_FILE);
                prop = e->getAttributeNS(NULL,_reloadInterval);
                if (prop && *prop)
                    crl.reloadInterval = XMLString::parseInt(prop);
            }
            e = XMLHelper::getNextSiblingElement(e,_URL);
        }
        if (m_crls.empty()) {
            log.error("Path/URL element missing inside CRL element");
            throw XMLSecurityException("FilesystemCredentialResolver can't access CRL, no Path or URL element specified.");
        }
    }

    // Check for Certificate
    DOMElement* certnode = XMLHelper::getFirstChildElement(root,Certificate);
    if (certnode) {
        prop = certnode->getAttributeNS(NULL,password);
        if (prop && *prop) {
            auto_ptr_char certpass(prop);
            m_certpass = certpass.get();
        }

        const XMLCh* certformat = certnode->getAttributeNS(NULL,_format);

        e = XMLHelper::getFirstChildElement(certnode);
        while (e) {
            if (e->hasChildNodes() && (XMLString::equals(e->getLocalName(), Path) || XMLString::equals(e->getLocalName(), CAPath))) {
                m_certs.push_back(ManagedCert());
                ManagedResource& cert = m_certs.back();
                if (certformat && *certformat) {
                    auto_ptr_char f(certformat);
                    cert.format = f.get();
                }
                prop = e->getFirstChild()->getNodeValue();
                auto_ptr_char certpath(prop);
                cert.source = certpath.get();
                XMLToolingConfig::getConfig().getPathResolver()->resolve(cert.source, PathResolver::XMLTOOLING_CFG_FILE);
                cert.local = true;
                prop = e->getAttributeNS(NULL,_reloadChanges);
                if (prop && (*prop==chLatin_f) || (*prop==chDigit_0))
                    cert.reloadChanges = false;
            }
            else if (e->hasChildNodes() && XMLString::equals(e->getLocalName(), _URL)) {
                m_certs.push_back(ManagedCert());
                ManagedResource& cert = m_certs.back();
                if (certformat && *certformat) {
                    auto_ptr_char f(certformat);
                    cert.format = f.get();
                }
                prop = e->getFirstChild()->getNodeValue();
                auto_ptr_char certpath(prop);
                cert.source = certpath.get();
                cert.local = false;
                prop = e->getAttributeNS(NULL,backingFilePath);
                if (!prop || !*prop)
                    throw XMLSecurityException("FilesystemCredentialResolver can't access certificate, backingFilePath missing from URL element.");
                auto_ptr_char b(prop);
                cert.backing = b.get();
                XMLToolingConfig::getConfig().getPathResolver()->resolve(cert.backing, PathResolver::XMLTOOLING_RUN_FILE);
                prop = e->getAttributeNS(NULL,_reloadInterval);
                if (prop && *prop)
                    cert.reloadInterval = XMLString::parseInt(prop);
            }
            e = XMLHelper::getNextSiblingElement(e);
        }
        if (m_certs.empty()) {
            log.error("Path/URL element missing inside Certificate element");
            throw XMLSecurityException("FilesystemCredentialResolver can't access certificate, no Path or URL element specified.");
        }
    }

    // Do an initial load of all the objects. If anything blows up here, whatever's
    // been loaded should be freed during teardown of the embedded objects.
    time_t now = time(NULL);
    m_key.filestamp = now;
    m_key.load(log, m_keypass.c_str());
    for (vector<ManagedCert>::iterator i = m_certs.begin(); i != m_certs.end(); ++i) {
        i->load(log, (i==m_certs.begin()) ? m_certpass.c_str() : NULL);
        i->filestamp = now;
    }
    for (vector<ManagedCRL>::iterator j = m_crls.begin(); j != m_crls.end(); ++j) {
        j->load(log);
        j->filestamp = now;
    }

    // Load it all into a credential object and then create the lock.
    auto_ptr<Credential> credential(getCredential());
    m_lock = RWLock::create();
    m_credential = credential.release();
}

FilesystemCredentialResolver::~FilesystemCredentialResolver()
{
    delete m_credential;
    delete m_lock;
}

Credential* FilesystemCredentialResolver::getCredential()
{
    // First, verify that the key and certificate match.
    if (m_key.key && !m_certs.empty()) {
        auto_ptr<XSECCryptoKey> temp(m_certs.front().certs.front()->clonePublicKey());
        if (!SecurityHelper::matches(m_key.key, temp.get()))
            throw XMLSecurityException("FilesystemCredentialResolver given mismatched key/certificate, check for consistency.");
    }

    // We (unfortunately) need to duplicate all the objects and put them in one set of arrays
    // in order to create the credential wrapper.
    FilesystemCredential* credential=NULL;
    auto_ptr<XSECCryptoKey> xseckey(m_key.key ? m_key.key->clone() : NULL);
    vector<XSECCryptoX509*> xseccerts;
    vector<XSECCryptoX509CRL*> xseccrls;
    try {
        for (vector<ManagedCert>::iterator i = m_certs.begin(); i != m_certs.end(); ++i) {
            for (vector<XSECCryptoX509*>::const_iterator y = i->certs.begin(); y != i->certs.end(); ++y)
                xseccerts.push_back(new OpenSSLCryptoX509(static_cast<OpenSSLCryptoX509*>(*y)->getOpenSSLX509()));
        }
        for (vector<ManagedCRL>::iterator j = m_crls.begin(); j != m_crls.end(); ++j) {
            for (vector<XSECCryptoX509CRL*>::const_iterator z = j->crls.begin(); z != j->crls.end(); ++z)
                xseccrls.push_back((*z)->clone());
        }
        credential = new FilesystemCredential(this, xseckey.get(), xseccerts, xseccrls);
        xseckey.release();
    }
    catch (exception&) {
        for_each(xseccerts.begin(), xseccerts.end(), xmltooling::cleanup<XSECCryptoX509>());
        for_each(xseccrls.begin(), xseccrls.end(), xmltooling::cleanup<XSECCryptoX509CRL>());
        throw;
    }

    // At this point the copies are owned by the credential.
    try {
        credential->initKeyInfo(m_keyinfomask);
    }
    catch (exception&) {
        delete credential;
        throw;
    }

    return credential;
}

Lockable* FilesystemCredentialResolver::lock()
{
#ifdef _DEBUG
    NDC ndc("lock");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT".CredentialResolver."FILESYSTEM_CREDENTIAL_RESOLVER);

    m_lock->rdlock();

    // Check each managed resource while holding a read lock for staleness.
    // If it comes back false, the lock is left as is, and the resource was stable.
    // If it comes back true, the lock was elevated to a write lock, and the resource
    // needs to be reloaded, and the credential replaced.
    // Once a stale check comes back true, further checks leave the lock alone.

    bool writelock = false, updated = false;

    if (m_key.stale(log, m_lock)) {
        writelock = true;
        try {
            m_key.load(log, m_keypass.c_str());
            updated = true;
        }
        catch (exception& ex) {
            log.crit("maintaining existing key: %s", ex.what());
        }
    }

    for (vector<ManagedCert>::iterator i = m_certs.begin(); i != m_certs.end(); ++i) {
        if (i->stale(log, writelock ? NULL : m_lock)) {
            writelock = true;
            try {
                i->load(log, (i==m_certs.begin()) ? m_certpass.c_str() : NULL);
                updated = true;
            }
            catch (exception& ex) {
                log.crit("maintaining existing certificate(s): %s", ex.what());
            }
        }
    }

    for (vector<ManagedCRL>::iterator j = m_crls.begin(); j != m_crls.end(); ++j) {
        if (j->stale(log, writelock ? NULL : m_lock)) {
            writelock = true;
            try {
                j->load(log);
                updated = true;
            }
            catch (exception& ex) {
                log.crit("maintaining existing CRL(s): %s", ex.what());
            }
        }
    }

    if (updated) {
        try {
            auto_ptr<Credential> credential(getCredential());
            delete m_credential;
            m_credential = credential.release();
        }
        catch (exception& ex) {
            log.crit("maintaining existing credentials, error reloading: %s", ex.what());
        }
    }

    if (writelock) {
        m_lock->unlock();
        m_lock->rdlock();
    }
    return this;
}

const Credential* FilesystemCredentialResolver::resolve(const CredentialCriteria* criteria) const
{
    return (criteria ? (criteria->matches(*m_credential) ? m_credential : NULL) : m_credential);
}

vector<const Credential*>::size_type FilesystemCredentialResolver::resolve(
    vector<const Credential*>& results, const CredentialCriteria* criteria
    ) const
{
    if (!criteria || criteria->matches(*m_credential)) {
        results.push_back(m_credential);
        return 1;
    }
    return 0;
}

// OpenSSL password callback...
static int passwd_callback(char* buf, int len, int verify, void* passwd)
{
    if(!verify)
    {
        if(passwd && len > strlen(reinterpret_cast<char*>(passwd)))
        {
            strcpy(buf,reinterpret_cast<char*>(passwd));
            return strlen(buf);
        }
    }
    return 0;
}

void FilesystemCredential::attach(SSL_CTX* ctx) const
{
#ifdef _DEBUG
    NDC ndc("attach");
#endif

    int ret=0;
    const char* path = m_resolver->m_key.local ? m_resolver->m_key.source.c_str() : m_resolver->m_key.backing.c_str();
    if (!path || !*path)
        throw XMLSecurityException("No key available, unable to attach private key to SSL context.");

    if (!m_resolver->m_keypass.empty()) {
        SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
        SSL_CTX_set_default_passwd_cb_userdata(ctx, const_cast<char*>(m_resolver->m_keypass.c_str()));
    }

    if (m_resolver->m_key.format == "PEM") {
        ret=SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM);
    }
    else if (m_resolver->m_key.format == "DER") {
        ret=SSL_CTX_use_RSAPrivateKey_file(ctx, path, SSL_FILETYPE_ASN1);
    }
    else if (m_resolver->m_key.format == "PKCS12") {
        BIO* in=BIO_new(BIO_s_file_internal());
        if (in && BIO_read_filename(in,path)>0) {
            PKCS12* p12 = d2i_PKCS12_bio(in, NULL);
            if (p12) {
                EVP_PKEY* pkey=NULL;
                X509* x=NULL;
                PKCS12_parse(p12, const_cast<char*>(m_resolver->m_keypass.c_str()), &pkey, &x, NULL);
                PKCS12_free(p12);
                if (x)
                    X509_free(x);
                if (pkey) {
                    ret=SSL_CTX_use_PrivateKey(ctx, pkey);
                    EVP_PKEY_free(pkey);
                }
            }
        }
        if (in)
            BIO_free(in);
    }

    if (ret!=1) {
        log_openssl();
        throw XMLSecurityException("Unable to attach private key to SSL context.");
    }

    // Attach certs.
    for (vector<XSECCryptoX509*>::const_iterator i=m_xseccerts.begin(); i!=m_xseccerts.end(); i++) {
        if (i==m_xseccerts.begin()) {
            if (SSL_CTX_use_certificate(ctx, static_cast<OpenSSLCryptoX509*>(*i)->getOpenSSLX509()) != 1) {
                log_openssl();
                throw XMLSecurityException("Unable to attach client certificate to SSL context.");
            }
        }
        else {
            // When we add certs, they don't get ref counted, so we need to duplicate them.
            X509* dup = X509_dup(static_cast<OpenSSLCryptoX509*>(*i)->getOpenSSLX509());
            if (SSL_CTX_add_extra_chain_cert(ctx, dup) != 1) {
                X509_free(dup);
                log_openssl();
                throw XMLSecurityException("Unable to attach CA certificate to SSL context.");
            }
        }
    }
}
