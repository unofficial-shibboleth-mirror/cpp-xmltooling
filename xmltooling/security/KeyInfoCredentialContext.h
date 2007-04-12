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
 * @file xmltooling/security/KeyInfoCredentialContext.h
 * 
 * Context for credentials resolved out of a KeyInfo.
 */

#if !defined(__xmltooling_keyinfocredctx_h__) && !defined(XMLTOOLING_NO_XMLSEC)
#define __xmltooling_keyinfocredctx_h__

#include <xmltooling/security/CredentialContext.h>
#include <xmltooling/signature/Signature.h>
#include <xsec/dsig/DSIGKeyInfoList.hpp>

namespace xmlsignature {
    class XMLTOOL_API KeyInfo;
}

namespace xmltooling {

    /**
     * Context for credentials resolved out of a KeyInfo.
     */
    class XMLTOOL_API KeyInfoCredentialContext : public CredentialContext
    {
    public:
        /**
         * Constructor
         */
        KeyInfoCredentialContext(const xmlsignature::KeyInfo* keyInfo=NULL) : m_keyInfo(keyInfo), m_nativeKeyInfo(NULL) {
        }

        /**
         * Constructor
         */
        KeyInfoCredentialContext(DSIGKeyInfoList* keyInfo) : m_keyInfo(NULL), m_nativeKeyInfo(keyInfo) {
        }

        virtual ~KeyInfoCredentialContext() {}

        /**
         * Gets the KeyInfo context.
         * 
         * @return the KeyInfo context
         */
        const xmlsignature::KeyInfo* getKeyInfo() const {
            return m_keyInfo;
        }

        /**
         * Gets the native KeyInfo context.
         * 
         * @return the native KeyInfo context
         */
        DSIGKeyInfoList* getNativeKeyInfo() const {
            return m_nativeKeyInfo;
        }

    private:
        const xmlsignature::KeyInfo* m_keyInfo;
        DSIGKeyInfoList* m_nativeKeyInfo;
    };
};

#endif /* __xmltooling_keyinfocredctx_h__ */
