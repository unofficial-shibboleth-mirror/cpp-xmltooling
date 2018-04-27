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

#include <xmltooling/logging.h>
#include <xmltooling/Lockable.h>

#include <ctime>
#include <string>
#include <boost/scoped_ptr.hpp>

class XSECCryptoSymmetricKey;

namespace xmltooling {

    class XMLTOOL_API DataSealerKeyStrategy : public virtual Lockable {
        MAKE_NONCOPYABLE(DataSealerKeyStrategy);
    public:
        virtual ~DataSealerKeyStrategy();

        /**
        * Get the default/current key to use for new operations, returned along with an identifier for it.
        *
        * @return  the key and its label
        */
        virtual std::pair<std::string, const XSECCryptoSymmetricKey*> getDefaultKey() const=0;

        /**
        * Get a specifically named key.
        *
        * @param name name of the key to retrieve
        *
        * @return  the key
        */
        virtual const XSECCryptoSymmetricKey* getKey(const char* name) const=0;

    protected:
        DataSealerKeyStrategy();
    };

    /**
    * Registers DataSealerKeyStrategy classes into the runtime.
    */
    void XMLTOOL_API registerDataSealerKeyStrategies();

    /** DataSealerKeyStrategy based on a single statically-defined key. */
    #define STATIC_DATA_SEALER_KEY_STRATEGY  "Static"

    /** DataSealerKeyStrategy based on versioned keys in a file. */
    #define VERSIONED_DATA_SEALER_KEY_STRATEGY  "Versioned"

    /**
    * Interface to a data integrity and confidentiality tool, and a default implementation.
    */
    class XMLTOOL_API DataSealer {
        MAKE_NONCOPYABLE(DataSealer);
    public:

        /**
        * Creates a data sealer on top of a particular key strategy.
        *
        * <p>Ownership of the DataSealerKeyStrategy is assumed by this object upon
		* successful construction.</p>
        *
        * @param strategy       pointer to a DataSealerKeyStrategy
        */
        DataSealer(DataSealerKeyStrategy* strategy);

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
        * @param s the data to wrap
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

    private:
		logging::Category& m_log;
		boost::scoped_ptr<DataSealerKeyStrategy> m_strategy;
    };

};

#endif /* __xmltooling_sealer_h__ */
