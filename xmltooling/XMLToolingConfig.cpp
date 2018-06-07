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
 * XMLToolingConfig.cpp
 *
 * Library configuration.
 */

#include "internal.h"
#include "exceptions.h"
#include "logging.h"
#include "XMLToolingConfig.h"
#include "encryption/Encryption.h"
#include "encryption/Encrypter.h"
#include "impl/UnknownElement.h"
#include "io/HTTPResponse.h"
#include "security/CredentialResolver.h"
#include "security/DataSealer.h"
#include "security/KeyInfoResolver.h"
#include "security/OpenSSLCryptoX509CRL.h"
#include "security/PathValidator.h"
#include "security/TrustEngine.h"
#include "signature/KeyInfo.h"
#include "signature/Signature.h"
#include "soap/SOAP.h"
#include "soap/SOAPTransport.h"
#include "util/NDC.h"
#include "util/PathResolver.h"
#include "util/ReplayCache.h"
#include "util/StorageService.h"
#include "util/TemplateEngine.h"
#include "util/Threads.h"
#include "util/URLEncoder.h"
#include "validation/ValidatorSuite.h"

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif

#include <stdexcept>
#include <boost/ptr_container/ptr_vector.hpp>

#if defined(XMLTOOLING_LOG4SHIB)
# include <log4shib/PropertyConfigurator.hh>
# include <log4shib/OstreamAppender.hh>
#elif defined(XMLTOOLING_LOG4CPP)
# include <log4cpp/PropertyConfigurator.hh>
# include <log4cpp/OstreamAppender.hh>
#endif
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#ifndef XMLTOOLING_NO_XMLSEC
# include <curl/curl.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include <xsec/framework/XSECAlgorithmMapper.hpp>
# include <xsec/framework/XSECException.hpp>
# include <xsec/framework/XSECProvider.hpp>
# include <xsec/transformers/TXFMBase.hpp>
#endif

using namespace soap11;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

DECL_XMLTOOLING_EXCEPTION_FACTORY(XMLParserException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(XMLObjectException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(MarshallingException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(UnmarshallingException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(UnknownElementException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(UnknownAttributeException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(UnknownExtensionException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ValidationException,xmltooling);
DECL_XMLTOOLING_EXCEPTION_FACTORY(IOException,xmltooling);

#ifndef XMLTOOLING_NO_XMLSEC
using namespace xmlencryption;
using namespace xmlsignature;
    DECL_XMLTOOLING_EXCEPTION_FACTORY(XMLSecurityException,xmltooling);
    DECL_XMLTOOLING_EXCEPTION_FACTORY(SignatureException,xmlsignature);
    DECL_XMLTOOLING_EXCEPTION_FACTORY(EncryptionException,xmlencryption);
#endif

namespace {
    static XMLToolingInternalConfig g_config;
#ifndef XMLTOOLING_NO_XMLSEC
// NOTE:
// "The old locking functions have been removed completely without compatibility macros"
// see:
// https://www.openssl.org/docs/manmaster/crypto/CRYPTO_THREAD_lock_free.html
//
// For now we just make the callback compile.  More work TBD
#ifndef CRYPTO_LOCK
#define CRYPTO_LOCK 1
#endif
    static ptr_vector<Mutex> g_openssl_locks;

    extern "C" void openssl_locking_callback(int mode,int n,const char *file,int line)
    {
        if (mode & CRYPTO_LOCK)
            g_openssl_locks[n].lock();
        else
            g_openssl_locks[n].unlock();
    }

# ifndef WIN32
    extern "C" unsigned long openssl_thread_id(void)
    {
        return (unsigned long)(pthread_self());
    }
# endif

    class TXFMOutputLog : public TXFMBase {
	    TXFMOutputLog();
    public:
        TXFMOutputLog(DOMDocument* doc) : TXFMBase(doc), m_log(Category::getInstance(XMLTOOLING_LOGCAT ".Signature.Debugger")) {
            input = nullptr;
        }
        ~TXFMOutputLog() {
            m_log.debug("\n----- END SIGNATURE DEBUG -----\n");
        }

	    void setInput(TXFMBase *newInput) {
	        input = newInput;
	        if (newInput->getOutputType() != TXFMBase::BYTE_STREAM)
		        throw XSECException(XSECException::TransformInputOutputFail, "OutputLog transform requires BYTE_STREAM input");
	        keepComments = input->getCommentsStatus();
            m_log.debug("\n----- BEGIN SIGNATURE DEBUG -----\n");
        }

	    TXFMBase::ioType getInputType() const {
            return TXFMBase::BYTE_STREAM;
        }
	    TXFMBase::ioType getOutputType() const {
            return TXFMBase::BYTE_STREAM;
        }
	    TXFMBase::nodeType getNodeType() const {
            return TXFMBase::DOM_NODE_NONE;
        }

	    unsigned int readBytes(XMLByte * const toFill, const unsigned int maxToFill) {
	        unsigned int sz = input->readBytes(toFill, maxToFill);
            m_log.debug(string(reinterpret_cast<char* const>(toFill), sz));
	        return sz;
        }
	
    private:
        Category& m_log;
    };

    TXFMBase* TXFMOutputLogFactory(DOMDocument* doc) {
        if (Category::getInstance(XMLTOOLING_LOGCAT ".Signature.Debugger").isDebugEnabled())
            return new TXFMOutputLog(doc);
        return nullptr;
    }

#endif

#ifdef WIN32
    BOOL LogEvent(
        LPCSTR  lpUNCServerName,
        WORD  wType,
        DWORD  dwEventID,
        PSID  lpUserSid,
        LPCSTR  message)
    {
        LPCSTR  messages[] = {message, nullptr};

        HANDLE hElog = RegisterEventSource(lpUNCServerName, "OpenSAML XMLTooling Library");
        BOOL res = ReportEvent(hElog, wType, 0, dwEventID, lpUserSid, 1, 0, messages, nullptr);
        return (DeregisterEventSource(hElog) && res);
    }
#endif
}

XMLToolingConfig& XMLToolingConfig::getConfig()
{
    return g_config;
}

XMLToolingInternalConfig& XMLToolingInternalConfig::getInternalConfig()
{
    return g_config;
}

XMLToolingConfig::XMLToolingConfig() : clock_skew_secs(180)
{
}

XMLToolingConfig::~XMLToolingConfig()
{
}

#ifndef XMLTOOLING_LITE
const KeyInfoResolver* XMLToolingConfig::getKeyInfoResolver() const
{
    return m_keyInfoResolver.get();
}

ReplayCache* XMLToolingConfig::getReplayCache() const
{
    return m_replayCache.get();
}

const DataSealer* XMLToolingConfig::getDataSealer() const
{
    return m_dataSealer.get();
}

void XMLToolingConfig::setKeyInfoResolver(xmltooling::KeyInfoResolver *keyInfoResolver)
{
    m_keyInfoResolver.reset(keyInfoResolver);
}

void XMLToolingConfig::setReplayCache(ReplayCache* replayCache)
{
    m_replayCache.reset(replayCache);
}

void XMLToolingConfig::setDataSealer(DataSealer* dataSealer)
{
    m_dataSealer.reset(dataSealer);
}
#endif

PathResolver* XMLToolingConfig::getPathResolver() const
{
    return m_pathResolver.get();
}

TemplateEngine* XMLToolingConfig::getTemplateEngine() const
{
    return m_templateEngine.get();
}

const URLEncoder* XMLToolingConfig::getURLEncoder() const
{
    return m_urlEncoder.get();
}

void XMLToolingConfig::setPathResolver(PathResolver* pathResolver)
{
    m_pathResolver.reset(pathResolver);
}

void XMLToolingConfig::setTemplateEngine(TemplateEngine* templateEngine)
{
    m_templateEngine.reset(templateEngine);
}

void XMLToolingConfig::setURLEncoder(URLEncoder* urlEncoder)
{
    m_urlEncoder.reset(urlEncoder);
}

XMLToolingInternalConfig::XMLToolingInternalConfig() : m_initCount(0), m_lock(Mutex::create())
{
}

XMLToolingInternalConfig::~XMLToolingInternalConfig()
{
}

bool XMLToolingInternalConfig::log_config(const char* config)
{
    try {
        if (!config || !*config)
            config=getenv("XMLTOOLING_LOG_CONFIG");
        if (!config || !*config)
            config="WARN";

        bool level=false;
        Category& root = Category::getRoot();
        if (!strcmp(config,"DEBUG")) {
            root.setPriority(Priority::DEBUG);
            level=true;
        }
        else if (!strcmp(config,"INFO")) {
            root.setPriority(Priority::INFO);
            level=true;
        }
        else if (!strcmp(config,"NOTICE")) {
            root.setPriority(Priority::NOTICE);
            level=true;
        }
        else if (!strcmp(config,"WARN")) {
            root.setPriority(Priority::WARN);
            level=true;
        }
        else if (!strcmp(config,"ERROR")) {
            root.setPriority(Priority::ERROR);
            level=true;
        }
        else if (!strcmp(config,"CRIT")) {
            root.setPriority(Priority::CRIT);
            level=true;
        }
        else if (!strcmp(config,"ALERT")) {
            root.setPriority(Priority::ALERT);
            level=true;
        }
        else if (!strcmp(config,"EMERG")) {
            root.setPriority(Priority::EMERG);
            level=true;
        }
        else if (!strcmp(config,"FATAL")) {
            root.setPriority(Priority::FATAL);
            level=true;
        }
        if (level) {
            root.setAppender(new OstreamAppender("default",&cerr));
        }
        else {
            string path(config);
            PropertyConfigurator::configure(m_pathResolver.get() ? m_pathResolver->resolve(path, PathResolver::XMLTOOLING_CFG_FILE) : path);
        }

#ifndef XMLTOOLING_NO_XMLSEC
        Category::getInstance(XMLTOOLING_LOGCAT ".Signature.Debugger").setAdditivity(false);
#endif
	}
    catch (const ConfigureFailure& e) {
        string msg = string("error in file permissions or logging configuration: ") + e.what();
        Category::getInstance(XMLTOOLING_LOGCAT ".Logging").crit(msg);
#ifdef WIN32
        LogEvent(nullptr, EVENTLOG_ERROR_TYPE, 2100, nullptr, msg.c_str());
#endif
        return false;
    }

    return true;
}

bool XMLToolingInternalConfig::init(bool deprecationSupport)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT ".Config");

    Lock initLock(m_lock);

    if (m_initCount == INT_MAX) {
        log.crit("library initialized too many times");
        return false;
    }

    if (m_initCount >= 1) {
        ++m_initCount;
        return true;
    }

    try {
        log.debug("library initialization started");

#ifndef XMLTOOLING_NO_XMLSEC
        if (curl_global_init(CURL_GLOBAL_ALL)) {
            log.fatal("failed to initialize libcurl, OpenSSL, or Winsock");
            return false;
        }
        curl_version_info_data* curlver = curl_version_info(CURLVERSION_NOW);
        if (curlver) {
            log.debug("libcurl %s initialization complete", curlver->version);
            if (!(curlver->features & CURL_VERSION_SSL)) {
                log.crit("libcurl lacks TLS/SSL support, this will greatly limit functionality");
            } else if (curlver->ssl_version && !strstr(curlver->ssl_version, "OpenSSL")) {
                log.crit("libcurl lacks OpenSSL-specific options, this will greatly limit functionality");
            }
        }
        else {
            log.debug("libcurl %s initialization complete", LIBCURL_VERSION);
        }
#endif

        XMLPlatformUtils::Initialize();
        log.debug("Xerces %s initialization complete", XERCES_FULLVERSIONDOT);

#ifndef XMLTOOLING_NO_XMLSEC
        XSECPlatformUtils::Initialise();
        XSECPlatformUtils::SetReferenceLoggingSink(TXFMOutputLogFactory);
        m_xsecProvider.reset(new XSECProvider());
        log.debug("XML-Security %s initialization complete", XSEC_FULLVERSIONDOT);
#endif

        m_parserPool.reset(new ParserPool());
        m_validatingPool.reset(new ParserPool(true,true));

        m_pathResolver.reset(new PathResolver());
        m_urlEncoder.reset(new URLEncoder());

        // default registrations
        XMLObjectBuilder::registerDefaultBuilder(new UnknownElementBuilder());

        registerSOAPClasses();

        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(XMLParserException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(XMLObjectException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(MarshallingException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(UnmarshallingException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(UnknownElementException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(UnknownAttributeException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ValidationException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(IOException,xmltooling);

#ifndef XMLTOOLING_NO_XMLSEC
        XMLObjectBuilder::registerBuilder(QName(xmlconstants::XMLSIG_NS,Signature::LOCAL_NAME),new SignatureBuilder());
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(XMLSecurityException,xmltooling);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(SignatureException,xmlsignature);
        REGISTER_XMLTOOLING_EXCEPTION_FACTORY(EncryptionException,xmlencryption);
        registerDataSealerKeyStrategies();
        registerKeyInfoClasses();
        registerEncryptionClasses();
        registerCredentialResolvers();
        registerKeyInfoResolvers();
        registerPathValidators();
        registerTrustEngines();
        registerXMLAlgorithms();
        m_keyInfoResolver.reset(KeyInfoResolverManager.newPlugin(INLINE_KEYINFO_RESOLVER,nullptr,deprecationSupport));
#endif

#ifndef XMLTOOLING_LITE
        registerStorageServices();
#endif
        registerSOAPTransports();
        initSOAPTransports();

        HTTPResponse::getAllowedSchemes().push_back("https");
        HTTPResponse::getAllowedSchemes().push_back("http");

        // Register xml:id as an ID attribute.
        static const XMLCh xmlid[] = UNICODE_LITERAL_2(i,d);
        AttributeExtensibleXMLObject::registerIDAttribute(QName(xmlconstants::XML_NS, xmlid));
    }
    catch (const xercesc::XMLException&) {
        log.fatal("caught exception while initializing Xerces");
#ifndef XMLTOOLING_NO_XMLSEC
        curl_global_cleanup();
#endif
        return false;
    }

#ifndef XMLTOOLING_NO_XMLSEC
    // Set up OpenSSL locking.
    for (int i=0; i<CRYPTO_num_locks(); i++)
        g_openssl_locks.push_back(Mutex::create());
    CRYPTO_set_locking_callback(openssl_locking_callback);
# ifndef WIN32
    CRYPTO_set_id_callback(openssl_thread_id);
# endif
#endif

    log.info("%s library initialization complete", PACKAGE_STRING);
    ++m_initCount;
    return true;
}

void XMLToolingInternalConfig::term()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("term");
#endif

    Lock initLock(m_lock);
    if (m_initCount == 0) {
        Category::getInstance(XMLTOOLING_LOGCAT ".Config").crit("term without corresponding init");
        return;
    }
    else if (--m_initCount > 0) {
        return;
    }

#ifndef XMLTOOLING_NO_XMLSEC
    CRYPTO_set_locking_callback(nullptr);
    g_openssl_locks.clear();
#endif

    SchemaValidators.destroyValidators();
    XMLObjectBuilder::destroyBuilders();
    XMLToolingException::deregisterFactories();
    AttributeExtensibleXMLObject::deregisterIDAttributes();

    termSOAPTransports();
    SOAPTransportManager.deregisterFactories();

#ifndef XMLTOOLING_LITE
    StorageServiceManager.deregisterFactories();
#endif

#ifndef XMLTOOLING_NO_XMLSEC
    TrustEngineManager.deregisterFactories();
    CredentialResolverManager.deregisterFactories();
    KeyInfoResolverManager.deregisterFactories();
    DataSealerKeyStrategyManager.deregisterFactories();
    m_algorithmMap.clear();

    m_keyInfoResolver.reset();
    m_replayCache.reset();
    m_dataSealer.reset();
#endif

    m_pathResolver.reset();
    m_templateEngine.reset();
    m_urlEncoder.reset();

    for (vector<void*>::reverse_iterator i=m_libhandles.rbegin(); i!=m_libhandles.rend(); i++) {
#if defined(WIN32)
        FARPROC fn=GetProcAddress(static_cast<HMODULE>(*i),"xmltooling_extension_term");
        if (fn)
            fn();
        FreeLibrary(static_cast<HMODULE>(*i));
#elif defined(HAVE_DLFCN_H)
        void (*fn)()=(void (*)())dlsym(*i,"xmltooling_extension_term");
        if (fn)
            fn();
        dlclose(*i);
#else
# error "Don't know about dynamic loading on this platform!"
#endif
    }
    m_libhandles.clear();

    m_parserPool.reset();
    m_validatingPool.reset();

    for_each(m_namedLocks.begin(), m_namedLocks.end(), cleanup_pair<string,Mutex>());
    m_namedLocks.clear();

#ifndef XMLTOOLING_NO_XMLSEC
    m_xsecProvider.reset();
    XSECPlatformUtils::Terminate();
#endif

    XMLPlatformUtils::Terminate();

#ifndef XMLTOOLING_NO_XMLSEC
    curl_global_cleanup();
#endif
   Category::getInstance(XMLTOOLING_LOGCAT ".Config").info("%s library shutdown complete", PACKAGE_STRING);
   Category::shutdown();
}

Lockable* XMLToolingInternalConfig::lock()
{
    m_lock->lock();
    return this;
}

void XMLToolingInternalConfig::unlock()
{
    m_lock->unlock();
}

Mutex& XMLToolingInternalConfig::getNamedMutex(const char* name)
{
    Locker glock(this);
    map<string,Mutex*>::const_iterator m = m_namedLocks.find(name);
    if (m != m_namedLocks.end())
        return *(m->second);
    Mutex* newlock = Mutex::create();
    m_namedLocks[name] = newlock;
    return *newlock;
}

bool XMLToolingInternalConfig::load_library(const char* path, void* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("LoadLibrary");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT ".Config");
    log.info("loading extension: %s", path);

    Locker locker(this);

    string resolved(path);
    m_pathResolver->resolve(resolved, PathResolver::XMLTOOLING_LIB_FILE);

#if defined(WIN32)
    HMODULE handle=nullptr;
    for (string::iterator i = resolved.begin(); i != resolved.end(); ++i)
        if (*i == '/')
            *i = '\\';

    UINT em=SetErrorMode(SEM_FAILCRITICALERRORS);
    try {
        handle=LoadLibraryEx(resolved.c_str(),nullptr,LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!handle)
             handle=LoadLibraryEx(resolved.c_str(),nullptr,0);
        if (!handle)
            throw runtime_error(string("unable to load extension library: ") + resolved);
        FARPROC fn=GetProcAddress(handle,"xmltooling_extension_init");
        if (!fn)
            throw runtime_error(string("unable to locate xmltooling_extension_init entry point: ") + resolved);
        if (reinterpret_cast<int(*)(void*)>(fn)(context)!=0)
            throw runtime_error(string("detected error in xmltooling_extension_init: ") + resolved);
        SetErrorMode(em);
    }
    catch(std::exception&) {
        if (handle)
            FreeLibrary(handle);
        SetErrorMode(em);
        throw;
    }

#elif defined(HAVE_DLFCN_H)
    void* handle=dlopen(resolved.c_str(),RTLD_LAZY);
    if (!handle)
        throw runtime_error(string("unable to load extension library '") + resolved + "': " + dlerror());
    int (*fn)(void*)=(int (*)(void*))(dlsym(handle,"xmltooling_extension_init"));
    if (!fn) {
        dlclose(handle);
        throw runtime_error(
            string("unable to locate xmltooling_extension_init entry point in '") + resolved + "': " +
                (dlerror() ? dlerror() : "unknown error")
            );
    }
    try {
        if (fn(context)!=0)
            throw runtime_error(string("detected error in xmltooling_extension_init in ") + resolved);
    }
    catch(std::exception&) {
        if (handle)
            dlclose(handle);
        throw;
    }
#else
# error "Don't know about dynamic loading on this platform!"
#endif
    m_libhandles.push_back(handle);
    log.info("loaded extension: %s", resolved.c_str());
    return true;
}

#ifndef XMLTOOLING_NO_XMLSEC

void xmltooling::log_openssl()
{
    const char* file;
    const char* data;
    int flags,line;

    unsigned long code=ERR_get_error_line_data(&file,&line,&data,&flags);
    while (code) {
        Category& log=Category::getInstance("OpenSSL");
        log.errorStream() << "error code: " << code << " in " << file << ", line " << line << logging::eol;
        if (data && (flags & ERR_TXT_STRING))
            log.errorStream() << "error data: " << data << logging::eol;
        code=ERR_get_error_line_data(&file,&line,&data,&flags);
    }
}

XSECCryptoX509CRL* XMLToolingInternalConfig::X509CRL() const
{
    return new OpenSSLCryptoX509CRL();
}

pair<const char*,unsigned int> XMLToolingInternalConfig::mapXMLAlgorithmToKeyAlgorithm(const XMLCh* xmlAlgorithm) const
{
    for (algmap_t::const_iterator i = m_algorithmMap.begin(); i != m_algorithmMap.end(); ++i) {
        algmap_t::value_type::second_type::const_iterator j = i->second.find(xmlAlgorithm);
        if (j != i->second.end())
            return pair<const char*,unsigned int>(j->second.first.c_str(), j->second.second);
    }
    return pair<const char*,unsigned int>(nullptr, 0);
}

void XMLToolingInternalConfig::registerXMLAlgorithm(
    const XMLCh* xmlAlgorithm, const char* keyAlgorithm, unsigned int size, XMLSecurityAlgorithmType type
    )
{
    m_algorithmMap[type][xmlAlgorithm] = pair<string,unsigned int>((keyAlgorithm ? keyAlgorithm : ""), size);
    // Authenticated encryption algorithms are also generic encryption algorithms.
    if (type == ALGTYPE_AUTHNENCRYPT)
        m_algorithmMap[ALGTYPE_ENCRYPT][xmlAlgorithm] = pair<string,unsigned int>((keyAlgorithm ? keyAlgorithm : ""), size);
}

bool XMLToolingInternalConfig::isXMLAlgorithmSupported(const XMLCh* xmlAlgorithm, XMLSecurityAlgorithmType type)
{
    try {
        // First check for basic support from the xmlsec layer.
        if (XSECPlatformUtils::g_algorithmMapper->mapURIToHandler(xmlAlgorithm)) {
            // Make sure the algorithm is registered.
            algmap_t::const_iterator i = m_algorithmMap.find(type);
            if (i != m_algorithmMap.end()) {
                algmap_t::value_type::second_type::const_iterator j = i->second.find(xmlAlgorithm);
                if (j != i->second.end())
                    return true;
            }
        }
    }
    catch (XSECException&) {
    }
    return false;
}

void XMLToolingInternalConfig::registerXMLAlgorithms()
{
    // The deal with all the macros is to try and figure out with no false positives whether
    // the OpenSSL version *and* the XML-Security version support the algorithms.

    // With ECDSA, XML-Security exports a public macro for OpenSSL's support, and any
    // versions of XML-Security that didn't provide the macro don't handle ECDSA anyway.
    // However, the SHA-224 variant was left out of the initial XML-Security release.

    // With AES and GCM, all supported XML-Security versions export a macro for OpenSSL's support.

    // With SHA2, only the very latest XML-Security exports a macro, but all the versions
    // will handle SHA2 *if* OpenSSL does. So we use our own macro to check OpenSSL's
    // support, and then add checks to see if specific versions are compiled out.

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIMD5, nullptr, 0, ALGTYPE_DIGEST);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURISHA1, nullptr, 0, ALGTYPE_DIGEST);
#if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA256)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURISHA224, nullptr, 0, ALGTYPE_DIGEST);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURISHA256, nullptr, 0, ALGTYPE_DIGEST);
#endif
#if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA512)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURISHA384, nullptr, 0, ALGTYPE_DIGEST);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURISHA512, nullptr, 0, ALGTYPE_DIGEST);
#endif

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIDSA_SHA1, "DSA", 0, ALGTYPE_SIGN);
#if defined(URI_ID_DSA_SHA256) && defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA256)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIDSA_SHA256, "DSA", 0, ALGTYPE_SIGN);
#endif

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_MD5, "RSA", 0, ALGTYPE_SIGN);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_SHA1, "RSA", 0, ALGTYPE_SIGN);
#if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA256)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_SHA224, "RSA", 0, ALGTYPE_SIGN);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_SHA256, "RSA", 0, ALGTYPE_SIGN);
#endif
#if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA512)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_SHA384, "RSA", 0, ALGTYPE_SIGN);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_SHA512, "RSA", 0, ALGTYPE_SIGN);
#endif

#ifdef XSEC_OPENSSL_HAVE_EC
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIECDSA_SHA1, "EC", 0, ALGTYPE_SIGN);
# if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA256)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIECDSA_SHA256, "EC", 0, ALGTYPE_SIGN);
#  ifdef URI_ID_ECDSA_SHA224
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIECDSA_SHA224, "EC", 0, ALGTYPE_SIGN);
#  endif
# endif
# if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA512)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIECDSA_SHA384, "EC", 0, ALGTYPE_SIGN);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIECDSA_SHA512, "EC", 0, ALGTYPE_SIGN);
# endif
#endif

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIHMAC_SHA1, "HMAC", 0, ALGTYPE_SIGN);
#if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA256)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIHMAC_SHA224, "HMAC", 0, ALGTYPE_SIGN);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIHMAC_SHA256, "HMAC", 0, ALGTYPE_SIGN);
#endif
#if defined(XSEC_OPENSSL_HAVE_SHA2) && !defined(OPENSSL_NO_SHA512)
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIHMAC_SHA384, "HMAC", 0, ALGTYPE_SIGN);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIHMAC_SHA512, "HMAC", 0, ALGTYPE_SIGN);
#endif

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_1_5, "RSA", 0, ALGTYPE_KEYENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_OAEP_MGFP1, "RSA", 0, ALGTYPE_KEYENCRYPT);
#ifdef URI_ID_RSA_OAEP
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIRSA_OAEP, "RSA", 0, ALGTYPE_KEYENCRYPT);
#endif

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURI3DES_CBC, "DESede", 192, ALGTYPE_ENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_3DES, "DESede", 192, ALGTYPE_KEYENCRYPT);

#ifdef XSEC_OPENSSL_HAVE_AES
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIAES128_CBC, "AES", 128, ALGTYPE_ENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_AES128, "AES", 128, ALGTYPE_KEYENCRYPT);

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIAES192_CBC, "AES", 192, ALGTYPE_ENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_AES192, "AES", 192, ALGTYPE_KEYENCRYPT);

    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIAES256_CBC, "AES", 256, ALGTYPE_ENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_AES256, "AES", 256, ALGTYPE_KEYENCRYPT);

# ifdef URI_ID_KW_AES128_PAD
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_AES128_PAD, "AES", 128, ALGTYPE_KEYENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_AES192_PAD, "AES", 192, ALGTYPE_KEYENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIKW_AES256_PAD, "AES", 256, ALGTYPE_KEYENCRYPT);
# endif
#endif

#ifdef XSEC_OPENSSL_HAVE_GCM
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIAES128_GCM, "AES", 128, ALGTYPE_AUTHNENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIAES192_GCM, "AES", 192, ALGTYPE_AUTHNENCRYPT);
    registerXMLAlgorithm(DSIGConstants::s_unicodeStrURIAES256_GCM, "AES", 256, ALGTYPE_AUTHNENCRYPT);
#endif
}

#endif

#ifdef WIN32

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_THREAD_DETACH || fdwReason == DLL_PROCESS_DETACH)
        ThreadKey::onDetach();
    return TRUE;
}

#endif
