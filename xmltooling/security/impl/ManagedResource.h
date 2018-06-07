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
 * ManagedResource.h
 *
 * Internal helper for managing local/remote sources of information.
 */

#include "internal.h"
#include "logging.h"
#include "soap/SOAPTransport.h"
#include "util/Threads.h"

#include <memory>
#include <sys/types.h>
#include <sys/stat.h>

namespace xmltooling {

    // The ManagedResource classes handle memory management, loading of the files
    // and staleness detection. A copy of the active objects is always stored in
    // these instances.

    class XMLTOOL_DLLLOCAL ManagedResource {
    protected:
        ManagedResource() : local(true), reloadChanges(true), m_deprecationSupport(true), filestamp(0), reloadInterval(0) {}
        ~ManagedResource() {}

        SOAPTransport* getTransport() {
            SOAPTransport::Address addr("ManagedResource", source.c_str(), source.c_str());
            std::string scheme(addr.m_endpoint, strchr(addr.m_endpoint,':') - addr.m_endpoint);
            SOAPTransport* ret = XMLToolingConfig::getConfig().SOAPTransportManager.newPlugin(scheme.c_str(), addr, m_deprecationSupport);
            if (ret)
                ret->setCacheTag(&cacheTag);
            return ret;
        }

    public:
        bool stale(logging::Category& log, RWLock* lock=nullptr) {
            if (local) {
                if (source.empty())
                    return false;
#ifdef WIN32
                struct _stat stat_buf;
                if (_stat(source.c_str(), &stat_buf) != 0) {
                    log.error("unable to stat local resource (%s)", source.c_str());
                    return false;
                }
#else
                struct stat stat_buf;
                if (stat(source.c_str(), &stat_buf) != 0) {
                    log.error("unable to stat local resource (%s)", source.c_str());	
                    return false;
                }
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
                time_t now = time(nullptr);

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

        bool local, reloadChanges, m_deprecationSupport;
        std::string source,backing,cacheTag;
        time_t filestamp,reloadInterval;
    };

};
