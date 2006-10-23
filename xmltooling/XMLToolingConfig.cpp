/*
 *  Copyright 2001-2006 Internet2
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
 * XMLToolingConfig.cpp
 * 
 * Library configuration 
 */

#include "internal.h"
#include "exceptions.h"
#include "XMLToolingConfig.h"
#include "encryption/Encryption.h"
#include "impl/UnknownElement.h"
#include "security/TrustEngine.h"
#include "security/OpenSSLCryptoX509CRL.h"
#include "signature/CredentialResolver.h"
#include "soap/SOAP.h"
#include "util/NDC.h"
#include "util/ReplayCache.h"
#include "util/StorageService.h"
#include "util/TemplateEngine.h"
#include "util/XMLConstants.h"
#include "validation/ValidatorSuite.h"

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif

#include <stdexcept>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/OstreamAppender.hh>
#include <xercesc/util/PlatformUtils.hpp>
#ifndef XMLTOOLING_NO_XMLSEC
    #include <xsec/framework/XSECProvider.hpp>
    #include <openssl/err.h>
#endif

using namespace soap11;
using namespace xmlencryption;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

DECL_EXCEPTION_FACTORY(XMLParserException,xmltooling);
DECL_EXCEPTION_FACTORY(XMLObjectException,xmltooling);
DECL_EXCEPTION_FACTORY(MarshallingException,xmltooling);
DECL_EXCEPTION_FACTORY(UnmarshallingException,xmltooling);
DECL_EXCEPTION_FACTORY(UnknownElementException,xmltooling);
DECL_EXCEPTION_FACTORY(UnknownAttributeException,xmltooling);
DECL_EXCEPTION_FACTORY(UnknownExtensionException,xmltooling);
DECL_EXCEPTION_FACTORY(ValidationException,xmltooling);
DECL_EXCEPTION_FACTORY(XMLSecurityException,xmltooling);
DECL_EXCEPTION_FACTORY(IOException,xmltooling);

#ifndef XMLTOOLING_NO_XMLSEC
    DECL_EXCEPTION_FACTORY(SignatureException,xmlsignature);
#endif

namespace xmltooling {
   XMLToolingInternalConfig g_config;
}

XMLToolingConfig& XMLToolingConfig::getConfig()
{
    return g_config;
}

XMLToolingInternalConfig& XMLToolingInternalConfig::getInternalConfig()
{
    return g_config;
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
        if (level)
            root.setAppender(new OstreamAppender("default",&cerr));
        else
            PropertyConfigurator::configure(config);
    }
    catch (const ConfigureFailure& e) {
        Category::getInstance(XMLTOOLING_LOGCAT".Logging").crit("failed to initialize log4cpp: %s", e.what());
        return false;
    }
    
    return true;
}

void XMLToolingConfig::setReplayCache(ReplayCache* replayCache)
{
    delete m_replayCache;
    m_replayCache = replayCache;
}

void XMLToolingConfig::setTemplateEngine(TemplateEngine* templateEngine)
{
    delete m_templateEngine;
    m_templateEngine = templateEngine;
}

bool XMLToolingInternalConfig::init()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT".XMLToolingConfig");
    try {
        log.debug("library initialization started");

        xercesc::XMLPlatformUtils::Initialize();
        log.debug("Xerces initialization complete");

#ifndef XMLTOOLING_NO_XMLSEC
        XSECPlatformUtils::Initialise();
        m_xsecProvider=new XSECProvider();
        log.debug("XMLSec initialization complete");
#endif

        m_parserPool=new ParserPool();
        m_validatingPool=new ParserPool(true,true);
        m_lock=xercesc::XMLPlatformUtils::makeMutex();
        
        // Load catalogs from path.
        if (!catalog_path.empty()) {
            char* catpath=strdup(catalog_path.c_str());
            char* sep=NULL;
            char* start=catpath;
            while (start && *start) {
                sep=strchr(start,PATH_SEPARATOR_CHAR);
                if (sep)
                    *sep=0;
                auto_ptr_XMLCh temp(start);
                m_validatingPool->loadCatalog(temp.get());
                start = sep ? sep + 1 : NULL;
            }
            free(catpath);
        }

        // default registrations
        XMLObjectBuilder::registerDefaultBuilder(new UnknownElementBuilder());

        registerKeyInfoClasses();
        registerEncryptionClasses();
        registerSOAPClasses();
        
        REGISTER_EXCEPTION_FACTORY(XMLParserException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(XMLObjectException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(MarshallingException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(UnmarshallingException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(UnknownElementException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(UnknownAttributeException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(ValidationException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(XMLSecurityException,xmltooling);
        REGISTER_EXCEPTION_FACTORY(IOException,xmltooling);
        
#ifndef XMLTOOLING_NO_XMLSEC
        XMLObjectBuilder::registerBuilder(QName(xmlconstants::XMLSIG_NS,Signature::LOCAL_NAME),new SignatureBuilder());
        REGISTER_EXCEPTION_FACTORY(SignatureException,xmlsignature);
        registerKeyResolvers();
        registerCredentialResolvers();
        registerTrustEngines();
#endif
        registerStorageServices();

        // Register xml:id as an ID attribute.        
        static const XMLCh xmlid[] = UNICODE_LITERAL_2(i,d);
        AttributeExtensibleXMLObject::registerIDAttribute(QName(xmlconstants::XML_NS, xmlid)); 
    }
    catch (const xercesc::XMLException&) {
        log.fatal("caught exception while initializing Xerces");
        return false;
    }

    log.info("library initialization complete");
    return true;
}

void XMLToolingInternalConfig::term()
{
    SchemaValidators.destroyValidators();
    XMLObjectBuilder::destroyBuilders();
    XMLToolingException::deregisterFactories();
    AttributeExtensibleXMLObject::deregisterIDAttributes();

#ifndef XMLTOOLING_NO_XMLSEC
    TrustEngineManager.deregisterFactories();
    CredentialResolverManager.deregisterFactories();
    KeyResolverManager.deregisterFactories();
#endif

    delete m_replayCache;
    m_replayCache = NULL;
    
    delete m_templateEngine;
    m_templateEngine = NULL;

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
    
    delete m_parserPool;
    m_parserPool=NULL;
    delete m_validatingPool;
    m_validatingPool=NULL;

#ifndef XMLTOOLING_NO_XMLSEC
    delete m_xsecProvider;
    m_xsecProvider=NULL;
    XSECPlatformUtils::Terminate();
#endif

    xercesc::XMLPlatformUtils::closeMutex(m_lock);
    m_lock=NULL;
    xercesc::XMLPlatformUtils::Terminate();

 #ifdef _DEBUG
    xmltooling::NDC ndc("term");
#endif
   Category::getInstance(XMLTOOLING_LOGCAT".XMLToolingConfig").info("library shutdown complete");
}

Lockable* XMLToolingInternalConfig::lock()
{
    xercesc::XMLPlatformUtils::lockMutex(m_lock);
    return this;
}

void XMLToolingInternalConfig::unlock()
{
    xercesc::XMLPlatformUtils::unlockMutex(m_lock);
}

bool XMLToolingInternalConfig::load_library(const char* path, void* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("LoadLibrary");
#endif
    Category& log=Category::getInstance(XMLTOOLING_LOGCAT".XMLToolingConfig");
    log.info("loading extension: %s", path);

    Locker locker(this);

#if defined(WIN32)
    HMODULE handle=NULL;
    char* fixed=const_cast<char*>(path);
    if (strchr(fixed,'/')) {
        fixed=strdup(path);
        char* p=fixed;
        while (p=strchr(p,'/'))
            *p='\\';
    }

    UINT em=SetErrorMode(SEM_FAILCRITICALERRORS);
    try {
        handle=LoadLibraryEx(fixed,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!handle)
             handle=LoadLibraryEx(fixed,NULL,0);
        if (!handle)
            throw runtime_error(string("unable to load extension library: ") + fixed);
        FARPROC fn=GetProcAddress(handle,"xmltooling_extension_init");
        if (!fn)
            throw runtime_error(string("unable to locate xmltooling_extension_init entry point: ") + fixed);
        if (reinterpret_cast<int(*)(void*)>(fn)(context)!=0)
            throw runtime_error(string("detected error in xmltooling_extension_init: ") + fixed);
        if (fixed!=path)
            free(fixed);
        SetErrorMode(em);
    }
    catch(runtime_error& e) {
        log.error(e.what());
        if (handle)
            FreeLibrary(handle);
        SetErrorMode(em);
        if (fixed!=path)
            free(fixed);
        return false;
    }

#elif defined(HAVE_DLFCN_H)
    void* handle=dlopen(path,RTLD_LAZY);
    if (!handle)
        throw runtime_error(string("unable to load extension library '") + path + "': " + dlerror());
    int (*fn)(void*)=(int (*)(void*))(dlsym(handle,"xmltooling_extension_init"));
    if (!fn) {
        dlclose(handle);
        throw runtime_error(
            string("unable to locate xmltooling_extension_init entry point in '") + path + "': " +
                (dlerror() ? dlerror() : "unknown error")
            );
    }
    try {
        if (fn(context)!=0)
            throw runtime_error(string("detected error in xmltooling_extension_init in ") + path);
    }
    catch(runtime_error& e) {
        log.error(e.what());
        if (handle)
            dlclose(handle);
        return false;
    }
#else
# error "Don't know about dynamic loading on this platform!"
#endif
    m_libhandles.push_back(handle);
    log.info("loaded extension: %s", path);
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
        log.errorStream() << "error code: " << code << " in " << file << ", line " << line << CategoryStream::ENDLINE;
        if (data && (flags & ERR_TXT_STRING))
            log.errorStream() << "error data: " << data << CategoryStream::ENDLINE;
        code=ERR_get_error_line_data(&file,&line,&data,&flags);
    }
}

XSECCryptoX509CRL* XMLToolingInternalConfig::X509CRL() const
{
    return new OpenSSLCryptoX509CRL();
}
#endif
