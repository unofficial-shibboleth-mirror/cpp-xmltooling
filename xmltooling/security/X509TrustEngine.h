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
 * @file xmltooling/security/X509TrustEngine.h
 * 
 * Extended TrustEngine interface that adds validation of X.509 credentials.
 */

#if !defined(__xmltooling_x509trust_h__) && !defined(XMLTOOLING_NO_XMLSEC)
#define __xmltooling_x509trust_h__

#include <xmltooling/security/TrustEngine.h>

namespace xmltooling {

    /**
     * Extended TrustEngine interface that adds validation of X.509 credentials.
     */
    class XMLTOOL_API X509TrustEngine : public TrustEngine {
    protected:
        /**
         * Constructor.
         * 
         * If a DOM is supplied, the following XML content is supported:
         * 
         * <ul>
         *  <li>&lt;KeyInfoResolver&gt; elements with a type attribute
         * </ul>
         * 
         * XML namespaces are ignored in the processing of this content.
         * 
         * @param e DOM to supply configuration for provider
         */
        X509TrustEngine(const xercesc::DOMElement* e=NULL) : TrustEngine(e) {}
        
    public:
        virtual ~X509TrustEngine() {}

        virtual bool validate(
            xmlsignature::Signature& sig,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=NULL
            ) const=0;

        virtual bool validate(
            const XMLCh* sigAlgorithm,
            const char* sig,
            xmlsignature::KeyInfo* keyInfo,
            const char* in,
            unsigned int in_len,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=NULL
            ) const=0;

        /**
         * Determines whether an X.509 credential is valid with respect to the
         * source of credentials supplied.
         * 
         * <p>It is the responsibility of the application to ensure that the credentials
         * supplied are in fact associated with the peer who presented the credential.
         * 
         * <p>If criteria with a peer name are supplied, the "name" of the EE certificate
         * may also be checked to ensure that it identifies the intended peer.
         * The peer name itself or implementation-specific rules based on the content of the
         * peer credentials may be applied. Implementations may omit this check if they
         * deem it unnecessary.
         * 
         * @param certEE        end-entity certificate to validate
         * @param certChain     the complete set of certificates presented for validation (includes certEE)
         * @param credResolver  a locked resolver to supply trusted peer credentials to the TrustEngine
         * @param criteria      criteria for selecting peer credentials
         */
        virtual bool validate(
            XSECCryptoX509* certEE,
            const std::vector<XSECCryptoX509*>& certChain,
            const CredentialResolver& credResolver,
            CredentialCriteria* criteria=NULL
            ) const=0;
    };
    
};

#endif /* __xmltooling_x509trust_h__ */
