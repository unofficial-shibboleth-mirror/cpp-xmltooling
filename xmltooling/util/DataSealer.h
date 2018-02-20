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
 * @file xmltooling/util/DataSealer.h
 * 
 * Generic data protection interface.
 */

#if !defined(__xmltooling_sealer_h__) && !defined(XMLTOOLING_NO_XMLSEC)
#define __xmltooling_sealer_h__

#include <xmltooling/base.h>

#include <ctime>
#include <string>

namespace xmltooling {

    /**
    * Interface to a data integrity and confidentiality tool, and a default implementation.
    */
    class XMLTOOL_API DataSealer {
        MAKE_NONCOPYABLE(DataSealer);
    public:
        DataSealer();

        virtual ~DataSealer();

        /**
        * Encodes data into an AEAD-encrypted blob, gzip(exp|data)
        *
        * <ul>
        * <li>exp = expiration time of the data; encoded into ISO format</li>
        * <li>data = the data; a UTF-8-encoded string</li>
        * </ul>
        *
        * <p>As part of encryption, the key alias is supplied as additional authenticated data
        * to the cipher. Afterwards, the encrypted data is prepended by the IV and then again by the alias
        * (in length-prefixed UTF-8 format), which identifies the key used. Finally the result is encoded
        * safely for ASCII use (e.g., base64).</p>
        *
        * @param data the data to wrap
        * @param exp expiration time
        * @return the encoded blob
        */
        virtual std::string wrap(const char* s, time_t exp) const;

        /**
        * Decrypts and verifies an encrypted bundle wrapped via this object.
        *
        * @param s the encoded blob
        *
        * @return the decrypted data, if it's unexpired
        */
        virtual std::string unwrap(const char* s) const;

    };

};

#endif /* __xmltooling_sealer_h__ */
