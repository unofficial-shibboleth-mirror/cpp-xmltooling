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
 * @file xmltooling/security/BasicX509Credential.h
 * 
 * Wraps an X.509-based Credential by storing key/cert objects inside. 
 */

#if !defined(__xmltooling_basicx509cred_h__) && !defined(XMLTOOLING_NO_XMLSEC)
#define __xmltooling_basicx509cred_h__

#include <xmltooling/security/X509Credential.h>
#include <xmltooling/signature/KeyInfo.h>

#include <algorithm>

namespace xmltooling {

    /**
     * Wraps an X.509-based Credential by storing key/cert objects inside.
     */
    class XMLTOOL_API BasicX509Credential : public virtual X509Credential
    {
    protected:
        /**
         * Constructor.
         * 
         * @param ownCerts  true iff any certificates subsequently stored should be freed by destructor
         */
        BasicX509Credential(bool ownCerts) : m_key(NULL), m_ownCerts(ownCerts), m_crl(NULL), m_keyInfo(NULL), m_compactKeyInfo(NULL) {
        }

        /**
         * Constructor.
         * 
         * @param key   key pair or secret key
         * @param certs array of X.509 certificates, the first entry being the entity certificate
         * @param crl   optional CRL
         */
        BasicX509Credential(XSECCryptoKey* key, const std::vector<XSECCryptoX509*>& certs, XSECCryptoX509CRL* crl=NULL)
                : m_key(key), m_xseccerts(certs), m_ownCerts(true), m_crl(crl), m_keyInfo(NULL), m_compactKeyInfo(NULL) {
        }

        /** The private/secret key/keypair. */
        XSECCryptoKey* m_key;

        /** Key names (derived from credential, KeyInfo, or both). */
        std::set<std::string> m_keyNames;

        /** The X.509 certificate chain. */
        std::vector<XSECCryptoX509*> m_xseccerts;

        /** Indicates whether to destroy certificates. */
        bool m_ownCerts;

        /** The X.509 CRL. */
        XSECCryptoX509CRL* m_crl;

        /** The KeyInfo object representing the information. */
        xmlsignature::KeyInfo* m_keyInfo;

        /** The KeyInfo object representing the information in compact form. */
        xmlsignature::KeyInfo* m_compactKeyInfo;

        /**
         * Initializes (or reinitializes) a ds:KeyInfo to represent the Credential.
         */
        void initKeyInfo();
        
    public:
        virtual ~BasicX509Credential();
        
        const char* getAlgorithm() const;
        unsigned int getKeySize() const;

        XSECCryptoKey* getPrivateKey() const {
            if (m_key) {
                XSECCryptoKey::KeyType type = m_key->getKeyType();
                if (type!=XSECCryptoKey::KEY_RSA_PUBLIC && type!=XSECCryptoKey::KEY_DSA_PUBLIC)
                    return m_key;
            }
            return NULL;
        }

        XSECCryptoKey* getPublicKey() const {
            if (m_key) {
                XSECCryptoKey::KeyType type = m_key->getKeyType();
                if (type!=XSECCryptoKey::KEY_RSA_PRIVATE && type!=XSECCryptoKey::KEY_DSA_PRIVATE)
                    return m_key;
            }
            return NULL;
        }
        
        const std::set<std::string>& getKeyNames() const {
            return m_keyNames;
        }

        xmlsignature::KeyInfo* getKeyInfo(bool compact=false) const {
            if (compact || !m_keyInfo)
                return m_compactKeyInfo ? m_compactKeyInfo->cloneKeyInfo() : NULL;
            return m_keyInfo->cloneKeyInfo();
        }
        
        const std::vector<XSECCryptoX509*>& getEntityCertificateChain() const {
            return m_xseccerts;
        }

        XSECCryptoX509CRL* getCRL() const {
            return m_crl;
        }
    };
};

#endif /* __xmltooling_basicx509cred_h__ */
