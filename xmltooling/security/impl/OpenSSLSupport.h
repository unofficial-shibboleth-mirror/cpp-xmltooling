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
 * @file xmltooling/impl/OpenSSLSupport.h
 *
 * Various functions and classes to abstract away some of the
 * differences introduced by (at least) OpenSSL 1.1
 */
#include <openssl/x509_vfy.h>

// X509_STORE_CTX becomes opaque

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#   define X509_STORE_CTX_get0_cert(_ctx_) ((_ctx_)->cert)
#   define X509_STORE_CTX_get0_untrusted(_ctx_) ((_ctx_)->untrusted)

#   define EVP_PKEY_get0_DSA(_pkey_) ((_pkey_)->pkey.dsa)
#   define EVP_PKEY_get0_RSA(_pkey_) ((_pkey_)->pkey.rsa)
#   define EVP_PKEY_get0_EC_KEY(_pkey_) ((_pkey_)->pkey.ec)
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10000000L)
#   define EVP_PKEY_id(_evp_) ((_evp_)->type)
#endif

// BIO_s_file and BIO_s_file_internal
// in 0.9.8 #define BIO_s_file          BIO_s_file_internal, uses both
// in 1.0.0 #define BIO_s_file_internal BIO_s_file, uses both
// in 1.0.1 #define BIO_s_file_internal BIO_s_file, uses both
// in 1.0.1 #define BIO_s_file_internal BIO_s_file, uses both
// in 1.1 no BIO_s_file_internal
#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
#   define BIO_s_file_internal BIO_s_file
#endif

namespace xmltooling {
    // RAII for the now opaque X509_STORE_CTX
    class X509StoreCtxRAII
    {
    public:
        X509StoreCtxRAII();

        ~X509StoreCtxRAII();

        X509_STORE_CTX *of(void);

        // the API to get the chain changed in OpenSSL1.1
        STACK_OF(X509) *get0Chain();

        void set0TrustedStack(STACK_OF(X509) *sk);

    private:
        X509_STORE_CTX *m_context;
    };


    const BIGNUM *DSA_get0_pubkey(const DSA *dsa);
    const BIGNUM *DSA_get0_privkey(const DSA *dsa);

    const BIGNUM *RSA_get0_n(const RSA *rsa);
    const BIGNUM *RSA_get0_d(const RSA *rsa);
    const BIGNUM *RSA_get0_e(const RSA *rsa);

}
