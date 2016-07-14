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

#include "internal.h"
#include <openssl/x509_vfy.h> 
#include <security/impl/OpenSSLSupport.h>

X509StoreCtxRAII::X509StoreCtxRAII() : m_context(X509_STORE_CTX_new()) {
}

X509StoreCtxRAII::~X509StoreCtxRAII() {
    if (m_context) {
        X509_STORE_CTX_free(m_context);
    }
}

X509_STORE_CTX *X509StoreCtxRAII::of(void) {
    return m_context;
}

// the API to get the chain changed in OpenSSL1.1

STACK_OF(X509) *X509StoreCtxRAII::get0Chain() {
    if (!m_context) {
        return nullptr;
    }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    return X509_STORE_CTX_get_chain(m_context);
#else
    return X509_STORE_CTX_get0_chain(m_context);
#endif
}

// the API to set the trusted stack changed in OpenSSL1.1
void X509StoreCtxRAII::set0TrustedStack(STACK_OF(X509) *sk) {
    if (m_context) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        X509_STORE_CTX_trusted_stack(m_context, sk);
#else
        X509_STORE_CTX_set0_trusted_stack(m_context, sk);
#endif
    }
}
