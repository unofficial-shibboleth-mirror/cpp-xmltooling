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
 * ReplayCache.cpp
 * 
 * Helper class on top of StorageService for detecting message replay. 
 */

#include "internal.h"
#include "logging.h"
#include "security/SecurityHelper.h"
#include "util/ReplayCache.h"

using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

ReplayCache::ReplayCache(StorageService* storage)
    : m_owned(storage==nullptr),
        m_storage(storage ? storage : XMLToolingConfig::getConfig().StorageServiceManager.newPlugin(MEMORY_STORAGE_SERVICE, nullptr, false)),
        m_storageCaps(m_storage->getCapabilities())
{
}

ReplayCache::~ReplayCache()
{
    if (m_owned)
        delete m_storage;
}

bool ReplayCache::check(const char* context, const char* s, time_t expires)
{
    if (strlen(context) > m_storageCaps.getContextSize()) {
        // This is a design/coding failure.
        Category::getInstance(XMLTOOLING_LOGCAT ".ReplayCache").error(
            "context (%s) too long for StorageService (limit %u)", context, m_storageCaps.getContextSize()
            );
        return false;
    }
    else if (strlen(s) > m_storageCaps.getKeySize()) {
        // This is something to work around with a hash.
#ifndef XMLTOOLING_NO_XMLSEC
        string h = SecurityHelper::doHash("SHA1", s, strlen(s));
        // In storage already?
        if (m_storage->readString(context, h.c_str()))
            return false;
        m_storage->createString(context, h.c_str(), "x", expires);
        return true;
#else
        Category::getInstance(XMLTOOLING_LOGCAT ".ReplayCache").error(
            "key (%s) too long for StorageService (limit %u)", s, m_storageCaps.getKeySize()
            );
        return false;
#endif
    }

    // In storage already?
    if (m_storage->readString(context, s))
        return false;
    m_storage->createString(context, s, "x", expires);
    return true;
}

bool ReplayCache::check(const char* context, const XMLCh* s, time_t expires)
{
    auto_ptr_char temp(s);
    return check(context, temp.get(), expires);
}
