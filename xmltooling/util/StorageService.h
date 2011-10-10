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
 * @file xmltooling/util/StorageService.h
 * 
 * Generic data storage interface.
 */

#if !defined(__xmltooling_storage_h__) && !defined(XMLTOOLING_LITE)
#define __xmltooling_storage_h__

#include <xmltooling/base.h>

#include <ctime>

namespace xmltooling {

    /**
     * Generic data storage facility for use by services that require
     * some degree of persistence. Implementations will vary in how much
     * persistence they can supply.
     * 
     * <p>Storage is divided into "contexts" identified by a string label.
     * Keys need to be unique only within a given context, so multiple
     * components can share a single storage service safely as long as they
     * use different labels.
     *
     * <p>The allowable sizes for contexts, keys, and short values can vary
     * and be reported by the implementation to callers, but MUST be at least
     * 255 bytes.
     */
    class XMLTOOL_API StorageService
    {
        MAKE_NONCOPYABLE(StorageService);
    public:
        virtual ~StorageService();

        class XMLTOOL_API Capabilities {
            MAKE_NONCOPYABLE(Capabilities);
            unsigned int m_contextSize, m_keySize, m_stringSize;
        public:
            /**
             * Constructor.
             *
             * @param contextSize   max size of context labels in characters
             * @param keysize       max size of keys in characters
             * @param stringSize    max size of string values in characters
             */
            Capabilities(unsigned int contextSize, unsigned int keySize, unsigned int stringSize);
            ~Capabilities();

            /**
             * Returns max size of context labels in characters
             * @return  max size of context labels in characters
             */
            unsigned int getContextSize() const;

            /**
             * Returns max size of keys in characters
             * @return  max size of keys in characters
             */
            unsigned int getKeySize() const;

            /**
             * Returns max size of string values in characters
             * @return  max size of string values in characters
             */
            unsigned int getStringSize() const;
        };
        
        /**
         * Returns the capabilities of the underlying service.
         * <p>If implementations support only the 255 character minimum, the default
         * implementation of this method will suffice.
         *
         * @return  a reference to an interface to access the service's capabilities
         */
        virtual const Capabilities& getCapabilities() const;

        /**
         * Creates a new "short" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @param value         null-terminated value
         * @param expiration    an expiration timestamp, after which the record can be purged
         * @return  true iff record was inserted, false iff a duplicate was found
         * 
         * @throws IOException  raised if fatal errors occur in the insertion process 
         */
        virtual bool createString(const char* context, const char* key, const char* value, time_t expiration)=0;
        
        /**
         * Returns an existing "short" record from the storage service.
         *
         * <p>The version parameter can be set for "If-Modified-Since" semantics.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @param pvalue        location in which to return the record value
         * @param pexpiration   location in which to return the expiration timestamp
         * @param version       if > 0, only copy back data if newer than supplied version
         * @return  the version of the record read back, or 0 if no record exists
         * 
         * @throws IOException  raised if errors occur in the read process 
         */
        virtual int readString(
            const char* context, const char* key, std::string* pvalue=nullptr, time_t* pexpiration=nullptr, int version=0
            )=0;

        /**
         * Updates an existing "short" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @param value         null-terminated value to store, or nullptr to leave alone
         * @param expiration    a new expiration timestamp, or 0 to leave alone
         * @param version       if > 0, only update if the current version matches this value
         * @return the version of the record after update, 0 if no record exists, or -1 if the version
         *  parameter is non-zero and does not match the current version before update (so the caller is out of sync)
         *    
         * @throws IOException  raised if errors occur in the update process 
         */
        virtual int updateString(
            const char* context, const char* key, const char* value=nullptr, time_t expiration=0, int version=0
            )=0;
        
        /**
         * Deletes an existing "short" record from the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @return true iff the record existed and was deleted
         *    
         * @throws IOException  raised if errors occur in the deletion process 
         */
        virtual bool deleteString(const char* context, const char* key)=0;
        
        /**
         * Creates a new "long" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @param value         null-terminated value of arbitrary length
         * @param expiration    an expiration timestamp, after which the record can be purged
         * @return  true iff record was inserted, false iff a duplicate was found
         * 
         * @throws IOException  raised if errors occur in the insertion process 
         */
        virtual bool createText(const char* context, const char* key, const char* value, time_t expiration)=0;
        
        /**
         * Returns an existing "long" record from the storage service.
         *
         * <p>The version parameter can be set for "If-Modified-Since" semantics.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @param pvalue        location in which to return the record value
         * @param pexpiration   location in which to return the expiration timestamp
         * @param version       if > 0, only copy back data if newer than supplied version
         * @return  the version of the record read back, or 0 if no record exists
         * 
         * @throws IOException  raised if errors occur in the read process 
         */
        virtual int readText(
            const char* context, const char* key, std::string* pvalue=nullptr, time_t* pexpiration=nullptr, int version=0
            )=0;

        /**
         * Updates an existing "long" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @param value         null-terminated value of arbitrary length to store, or nullptr to leave alone
         * @param expiration    a new expiration timestamp, or 0 to leave alone
         * @param version       if > 0, only update if the current version matches this value
         * @return the version of the record after update, 0 if no record exists, or -1 if the version
         *  parameter is non-zero and does not match the current version before update (so the caller is out of sync)
         *    
         * @throws IOException  raised if errors occur in the update process 
         */
        virtual int updateText(
            const char* context, const char* key, const char* value=nullptr, time_t expiration=0, int version=0
            )=0;
        
        /**
         * Deletes an existing "long" record from the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key
         * @return true iff the record existed and was deleted
         *    
         * @throws IOException  raised if errors occur in the deletion process 
         */
        virtual bool deleteText(const char* context, const char* key)=0;
        
        /**
         * Manually trigger a cleanup of expired records.
         * The method <strong>MAY</strong> return without guaranteeing that
         * cleanup has already occurred.
         * 
         * @param context       a storage context label
         */
        virtual void reap(const char* context)=0;
        
        /**
         * Updates the expiration time of all records in the context.
         * 
         * @param context       a storage context label
         * @param expiration    a new expiration timestamp
         */
        virtual void updateContext(const char* context, time_t expiration)=0;

        /**
         * Forcibly removes all records in a given context along with any
         * associated resources devoted to maintaining the context.
         * 
         * @param context       a storage context label
         */
        virtual void deleteContext(const char* context)=0;

    protected:
        StorageService();
    };

    /**
     * Registers StorageService classes into the runtime.
     */
    void XMLTOOL_API registerStorageServices();

    /** StorageService based on in-memory caching. */
    #define MEMORY_STORAGE_SERVICE  "Memory"
};

#endif /* __xmltooling_storage_h__ */
