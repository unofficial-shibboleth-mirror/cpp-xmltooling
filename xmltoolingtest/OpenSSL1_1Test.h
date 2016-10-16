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

#define XSEC_HAVE_OPENSSL 1

#include "XMLObjectBaseTestCase.h"
#include <xmltooling/security/SecurityHelper.h>

#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>

# include <openssl/rsa.h>
# include <openssl/evp.h>
# include <openssl/bn.h>

class OpenSSL1_1Test : public CxxTest::TestSuite {
public:
    void setUp() {
    }

    void tearDown() {
    }
    void testRSA() {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000)
        string pathname = data_path + "key.pem";
        auto_ptr<OpenSSLCryptoKeyRSA> key1(dynamic_cast<OpenSSLCryptoKeyRSA*>(SecurityHelper::loadKeyFromFile(pathname.c_str())));
        
        auto_ptr<OpenSSLCryptoKeyRSA> key2(dynamic_cast<OpenSSLCryptoKeyRSA*>(key1->clone()));
        TSM_ASSERT("Cloned RSA Differs", deepEquals(key1.get(), key2.get()));
        TSM_ASSERT("Public Matches", SecurityHelper::matches(*key1.get(), *key2.get()));

#if 0 // This doesn't work - you cannot get private only RSA keys
        RSA *rsa = RSA_new();
        const BIGNUM *d;
        RSA_get0_key(key1->getOpenSSLRSA(), NULL, NULL, &d);
        BIGNUM *newD = BN_dup(d);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        rsa->d = newD;
#else
        RSA_set0_key(rsa, NULL, NULL, newD);
#endif
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
        auto_ptr<OpenSSLCryptoKeyRSA> privateOnly(new OpenSSLCryptoKeyRSA(pkey));
        EVP_PKEY_free(pkey);

        TSM_ASSERT("Private Matches", SecurityHelper::matches(*privateOnly.get(),*key1.get()));
#endif
#endif
    }

private:

#if (OPENSSL_VERSION_NUMBER >= 0x10100000)

    static bool deepEquals(OpenSSLCryptoKeyRSA * key1, OpenSSLCryptoKeyRSA *key2) {
        if (key1->getKeyType() != key2->getKeyType())
            return false;

        RSA *rsa1 = key1->getOpenSSLRSA();
        RSA *rsa2 = key2->getOpenSSLRSA();

        const BIGNUM *e1, *e2, *d1, *d2, *n1, *n2;
        RSA_get0_key(rsa1, &n1, &e1, &d1);
        RSA_get0_key(rsa2, &n2, &e2, &d2);
        if (BN_cmp(n1, n2) != 0 || BN_cmp(e1, e2) != 0 || BN_cmp(d1, d2) != 0)
            return false;

        const BIGNUM *dmp11, *dmq11, *iqmp1;
        RSA_get0_crt_params(rsa1, &dmp11, &dmq11, &iqmp1);
        const BIGNUM *dmp12, *dmq12, *iqmp2;
        RSA_get0_crt_params(rsa2, &dmp12, &dmq12, &iqmp2);
        if (BN_cmp(dmp11, dmp12) != 0 || BN_cmp(dmq11, dmq12) != 0 || BN_cmp(iqmp1, iqmp2) != 0)
            return false;

        const BIGNUM *p1, *p2, *q1, *q2;
        RSA_get0_factors(rsa1, &p1, &q1);
        RSA_get0_factors(rsa2, &p2, &q2);
        if (BN_cmp(p1, p2) != 0 || BN_cmp(q1, q2) != 0 )
            return false;

        return true;
    }
#endif
};