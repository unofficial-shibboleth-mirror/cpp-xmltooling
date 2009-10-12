/*
 * Copyright 2001-2009 The Apache Software Foundation.
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
 * @file xmltooling/security/OpenSSLCryptoX509CRL.h
 * 
 * OpenSSL-based class for handling X.509 CRLs.
 */

#if !defined(__xmltooling_opensslx509crl_h__) && !defined(XMLTOOLING_NO_XMLSEC)
#define __xmltooling_opensslx509crl_h__

#include <xmltooling/security/XSECCryptoX509CRL.h>

#include <openssl/x509v3.h>
#include <xsec/utils/XSECSafeBuffer.hpp>

namespace xmltooling {
    /**
     * OpenSSL-based class for handling X.509 CRLs
     */
    class XMLTOOL_API OpenSSLCryptoX509CRL : public XSECCryptoX509CRL {
    public:
        /** Default constructor. */
    	OpenSSLCryptoX509CRL();
    	virtual ~OpenSSLCryptoX509CRL();

    	const XMLCh* getProviderName() const;
    	void loadX509CRLBase64Bin(const char* buf, unsigned int len);
    	safeBuffer& getDEREncodingSB();
    
        /**
         * Constructor
         * 
         * @param x a native CRL object
         */
    	OpenSSLCryptoX509CRL(X509_CRL* x);
        
        /**
         * Returns native CRL object.
         * 
         * @return  native CRL object, or NULL
         */
    	X509_CRL* getOpenSSLX509CRL();

        XSECCryptoX509CRL* clone() const;
    
    private:
    	X509_CRL* mp_X509CRL;
    	safeBuffer m_DERX509CRL;
    };
};

#endif /* __xmltooling_opensslx509crl_h__ */

