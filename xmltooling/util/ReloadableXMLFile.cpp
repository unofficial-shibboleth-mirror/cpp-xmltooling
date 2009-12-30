/*
 *  Copyright 2001-2009 Internet2
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
 * @file ReloadableXMLFile.cpp
 *
 * Base class for file-based XML configuration.
 */

#include "internal.h"
#include "io/HTTPResponse.h"
#include "util/NDC.h"
#include "util/PathResolver.h"
#include "util/ReloadableXMLFile.h"
#include "util/Threads.h"
#include "util/XMLConstants.h"
#include "util/XMLHelper.h"

#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>

#include <xercesc/framework/LocalFileInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

static const XMLCh uri[] =              UNICODE_LITERAL_3(u,r,i);
static const XMLCh url[] =              UNICODE_LITERAL_3(u,r,l);
static const XMLCh path[] =             UNICODE_LITERAL_4(p,a,t,h);
static const XMLCh pathname[] =         UNICODE_LITERAL_8(p,a,t,h,n,a,m,e);
static const XMLCh file[] =             UNICODE_LITERAL_4(f,i,l,e);
static const XMLCh filename[] =         UNICODE_LITERAL_8(f,i,l,e,n,a,m,e);
static const XMLCh validate[] =         UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
static const XMLCh reloadChanges[] =    UNICODE_LITERAL_13(r,e,l,o,a,d,C,h,a,n,g,e,s);
static const XMLCh reloadInterval[] =   UNICODE_LITERAL_14(r,e,l,o,a,d,I,n,t,e,r,v,a,l);
static const XMLCh backingFilePath[] =  UNICODE_LITERAL_15(b,a,c,k,i,n,g,F,i,l,e,P,a,t,h);


ReloadableXMLFile::~ReloadableXMLFile()
{
    delete m_lock;
}

ReloadableXMLFile::ReloadableXMLFile(const DOMElement* e, Category& log)
    : m_root(e), m_local(true), m_validate(false), m_filestamp(0), m_reloadInterval(0), m_lock(NULL), m_log(log)
{
#ifdef _DEBUG
    NDC ndc("ReloadableXMLFile");
#endif

    // Establish source of data...
    const XMLCh* source=e->getAttributeNS(NULL,uri);
    if (!source || !*source) {
        source=e->getAttributeNS(NULL,url);
        if (!source || !*source) {
            source=e->getAttributeNS(NULL,path);
            if (!source || !*source) {
                source=e->getAttributeNS(NULL,pathname);
                if (!source || !*source) {
                    source=e->getAttributeNS(NULL,file);
                    if (!source || !*source) {
                        source=e->getAttributeNS(NULL,filename);
                    }
                }
            }
        }
        else
            m_local=false;
    }
    else
        m_local=false;

    if (source && *source) {
        const XMLCh* flag=e->getAttributeNS(NULL,validate);
        m_validate=(XMLString::equals(flag,xmlconstants::XML_TRUE) || XMLString::equals(flag,xmlconstants::XML_ONE));

        auto_ptr_char temp(source);
        m_source=temp.get();

        if (!m_local && !strstr(m_source.c_str(),"://")) {
            log.warn("deprecated usage of uri/url attribute for a local resource, use path instead");
            m_local=true;
        }

        if (m_local) {
            XMLToolingConfig::getConfig().getPathResolver()->resolve(m_source, PathResolver::XMLTOOLING_CFG_FILE);

            flag=e->getAttributeNS(NULL,reloadChanges);
            if (!XMLString::equals(flag,xmlconstants::XML_FALSE) && !XMLString::equals(flag,xmlconstants::XML_ZERO)) {
#ifdef WIN32
                struct _stat stat_buf;
                if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
                struct stat stat_buf;
                if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
                    m_filestamp=stat_buf.st_mtime;
                else
                    throw IOException("Unable to access local file ($1)", params(1,m_source.c_str()));
                m_lock=RWLock::create();
            }
            log.debug("using local resource (%s), will %smonitor for changes", m_source.c_str(), m_lock ? "" : "not ");
        }
        else {
            log.debug("using remote resource (%s)", m_source.c_str());
            source = e->getAttributeNS(NULL,backingFilePath);
            if (source && *source) {
                auto_ptr_char temp2(source);
                m_backing=temp2.get();
                XMLToolingConfig::getConfig().getPathResolver()->resolve(m_backing, PathResolver::XMLTOOLING_RUN_FILE);
                log.debug("backup remote resource with (%s)", m_backing.c_str());
            }
            source = e->getAttributeNS(NULL,reloadInterval);
            if (source && *source) {
                m_reloadInterval = XMLString::parseInt(source);
                if (m_reloadInterval > 0) {
                    m_log.debug("will reload remote resource at most every %d seconds", m_reloadInterval);
                    m_lock=RWLock::create();
                }
            }
            m_filestamp = time(NULL);   // assume it gets loaded initially
        }
    }
    else {
        log.debug("no resource uri/path/name supplied, will load inline configuration");
    }
}

pair<bool,DOMElement*> ReloadableXMLFile::load(bool backup)
{
#ifdef _DEBUG
    NDC ndc("init");
#endif

    try {
        if (m_source.empty()) {
            // Data comes from the DOM we were handed.
            m_log.debug("loading inline configuration...");
            return make_pair(false,XMLHelper::getFirstChildElement(m_root));
        }
        else {
            // Data comes from a file we have to parse.
            if (backup)
                m_log.warn("using local backup of remote resource");
            else
                m_log.debug("loading configuration from external resource...");

            DOMDocument* doc=NULL;
            if (m_local || backup) {
                auto_ptr_XMLCh widenit(backup ? m_backing.c_str() : m_source.c_str());
                LocalFileInputSource src(widenit.get());
                Wrapper4InputSource dsrc(&src,false);
                if (m_validate)
                    doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
                else
                    doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);
            }
            else {
                URLInputSource src(m_root, NULL, &m_cacheTag);
                Wrapper4InputSource dsrc(&src,false);
                if (m_validate)
                    doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
                else
                    doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);

                // Check for a response code signal.
                if (XMLHelper::isNodeNamed(doc->getDocumentElement(), xmlconstants::XMLTOOLING_NS, URLInputSource::utf16StatusCodeElementName)) {
                    int responseCode = XMLString::parseInt(doc->getDocumentElement()->getFirstChild()->getNodeValue());
                    doc->release();
                    if (responseCode == HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED) {
                        throw responseCode; // toss out as a "known" case to handle gracefully
                    }
                    else {
                        m_log.warn("remote resource fetch returned atypical status code (%d)", responseCode);
                        throw IOException("remote resource fetch failed, check log for status code of response");
                    }
                }
            }

            m_log.infoStream() << "loaded XML resource (" << (backup ? m_backing : m_source) << ")" << logging::eol;

            if (!backup && !m_backing.empty()) {
                m_log.debug("backing up remote resource to (%s)", m_backing.c_str());
                try {
                    ofstream backer(m_backing.c_str());
                    backer << *doc;
                }
                catch (exception& ex) {
                    m_log.crit("exception while backing up resource: %s", ex.what());
                }
            }

            return make_pair(true,doc->getDocumentElement());
        }
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        m_log.errorStream() << "Xerces error while loading resource (" << (backup ? m_backing : m_source) << "): "
            << msg.get() << logging::eol;
        if (!backup && !m_backing.empty())
            return load(true);
        throw XMLParserException(msg.get());
    }
    catch (exception& e) {
        m_log.errorStream() << "error while loading resource ("
            << (m_source.empty() ? "inline" : (backup ? m_backing : m_source)) << "): " << e.what() << logging::eol;
        if (!backup && !m_backing.empty())
            return load(true);
        throw;
    }
}

Lockable* ReloadableXMLFile::lock()
{
    if (!m_lock)
        return this;

    m_lock->rdlock();

    // Check if we need to refresh.
    if (m_local) {
#ifdef WIN32
        struct _stat stat_buf;
        if (_stat(m_source.c_str(), &stat_buf) != 0)
            return this;
#else
        struct stat stat_buf;
        if (stat(m_source.c_str(), &stat_buf) != 0)
            return this;
#endif
        if (m_filestamp>=stat_buf.st_mtime)
            return this;

        // Elevate lock and recheck.
        m_log.debug("timestamp of local resource changed, elevating to a write lock");
        m_lock->unlock();
        m_lock->wrlock();
        if (m_filestamp>=stat_buf.st_mtime) {
            // Somebody else handled it, just downgrade.
            m_log.debug("update of local resource handled by another thread, downgrading lock");
            m_lock->unlock();
            m_lock->rdlock();
            return this;
        }

        // Update the timestamp regardless. No point in repeatedly trying.
        m_filestamp=stat_buf.st_mtime;
        m_log.info("change detected, reloading local resource...");
    }
    else {
        time_t now = time(NULL);

        // Time to reload? If we have no data, filestamp is zero
        // and there's no way current time is less than the interval.
        if (now - m_filestamp < m_reloadInterval)
            return this;

        // Elevate lock and recheck.
        m_log.debug("reload interval for remote resource elapsed, elevating to a write lock");
        m_lock->unlock();
        m_lock->wrlock();
        if (now - m_filestamp < m_reloadInterval) {
            // Somebody else handled it, just downgrade.
            m_log.debug("update of remote resource handled by another thread, downgrading lock");
            m_lock->unlock();
            m_lock->rdlock();
            return this;
        }

        m_filestamp = now;
        m_log.info("reloading remote resource...");
    }

    // Do this once...
    try {
        // At this point we're holding the write lock, so make sure we pop it.
        SharedLock lockwrap(m_lock,false);
        pair<bool,DOMElement*> ret=load();
        if (ret.first)
            ret.second->getOwnerDocument()->release();
    }
    catch (int& ex) {
        if (ex == HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED) {
            m_log.info("remote resource (%s) unchanged from cached version", m_source.c_str());
        }
        else {
            // Shouldn't happen, we should only get codes intended to be gracefully handled.
            m_log.crit("maintaining existing configuration, remote resource fetch returned atypical status code (%d)", ex);
        }
    }
    catch (exception& ex) {
        m_log.crit("maintaining existing configuration, error reloading resource (%s): %s", m_source.c_str(), ex.what());
    }

    // If we made it here, the swap may or may not have worked, but we need to relock.
    m_log.debug("attempt to update resource complete, relocking");
    m_lock->rdlock();
    return this;
}

void ReloadableXMLFile::unlock()
{
    if (m_lock)
        m_lock->unlock();
}

pair<bool,DOMElement*> ReloadableXMLFile::load()
{
    return load(false);
}
