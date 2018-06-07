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
 * TrustEngine.cpp
 * 
 * Registration of factories for built-in engines.
 */

#include "internal.h"
#include "security/KeyInfoResolver.h"
#include "security/SignatureTrustEngine.h"
#include "security/OpenSSLTrustEngine.h"
#include "util/XMLHelper.h"

#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmltooling;
using namespace std;

using xercesc::DOMElement;

namespace xmltooling {
    XMLTOOL_DLLLOCAL PluginManager<TrustEngine,string,const DOMElement*>::Factory ExplicitKeyTrustEngineFactory;
#ifndef CPPXT_107_VC16
    XMLTOOL_DLLLOCAL PluginManager<TrustEngine,string,const DOMElement*>::Factory StaticPKIXTrustEngineFactory;
#endif
    XMLTOOL_DLLLOCAL PluginManager<TrustEngine,string,const DOMElement*>::Factory ChainingTrustEngineFactory;
};

void XMLTOOL_API xmltooling::registerTrustEngines()
{
    XMLToolingConfig& conf=XMLToolingConfig::getConfig();
    conf.TrustEngineManager.registerFactory(EXPLICIT_KEY_TRUSTENGINE, ExplicitKeyTrustEngineFactory);
    conf.TrustEngineManager.registerFactory(STATIC_PKIX_TRUSTENGINE, StaticPKIXTrustEngineFactory);
    conf.TrustEngineManager.registerFactory(CHAINING_TRUSTENGINE, ChainingTrustEngineFactory);
}

static const XMLCh _KeyInfoResolver[] = UNICODE_LITERAL_15(K,e,y,I,n,f,o,R,e,s,o,l,v,e,r);
static const XMLCh type[] =             UNICODE_LITERAL_4(t,y,p,e);

TrustEngine::TrustEngine(const DOMElement* e, bool deprecationSupport) : m_keyInfoResolver(nullptr)
{
    DOMElement* child = e ? XMLHelper::getFirstChildElement(e, _KeyInfoResolver) : nullptr;
    if (child) {
        string t = XMLHelper::getAttrString(child, nullptr, type);
        if (!t.empty())
            m_keyInfoResolver = XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(t.c_str(), child, deprecationSupport);
        else
            throw UnknownExtensionException("<KeyInfoResolver> element found with no type attribute");
    }
}

TrustEngine::~TrustEngine()
{
    delete m_keyInfoResolver;
}

SignatureTrustEngine::SignatureTrustEngine(const DOMElement* e, bool deprecationSupport) : TrustEngine(e, deprecationSupport)
{
}

SignatureTrustEngine::~SignatureTrustEngine()
{
}

X509TrustEngine::X509TrustEngine(const DOMElement* e, bool deprecationSupport) : TrustEngine(e, deprecationSupport)
{
}

X509TrustEngine::~X509TrustEngine()
{
}

OpenSSLTrustEngine::OpenSSLTrustEngine(const DOMElement* e, bool deprecationSupport) : X509TrustEngine(e, deprecationSupport)
{
}

OpenSSLTrustEngine::~OpenSSLTrustEngine()
{
}
