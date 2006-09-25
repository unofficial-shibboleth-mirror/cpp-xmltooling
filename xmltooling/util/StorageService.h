/*
 *  Copyright 2001-2006 Internet2
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
 * @file xmltooling/util/StorageService.h
 * 
 * Generic data storage interface
 */

#ifndef __xmltooling_storage_h__
#define __xmltooling_storage_h__

#include <xmltooling/XMLObject.h>

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
     */
    class XMLTOOL_API StorageService
    {
        MAKE_NONCOPYABLE(StorageService);
    public:
        virtual ~StorageService() {}
        
        /**
         * Creates a new "short" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @param value         null-terminated value of up to 255 bytes to store
         * @param expiration    an expiration timestamp, after which the record can be purged
         * 
         * @throws IOException  raised if errors occur in the insertion process 
         */
        virtual void createString(const char* context, const char* key, const char* value, time_t expiration)=0;
        
        /**
         * Returns an existing "short" record from the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @param pvalue        location in which to return the record value
         * @param pexpiration   location in which to return the expiration timestamp
         * @return  true iff a valid record exists and was returned   
         * 
         * @throws IOException  raised if errors occur in the read process 
         */
        virtual bool readString(const char* context, const char* key, std::string* pvalue=NULL, time_t* pexpiration=NULL)=0;

        /**
         * Updates an existing "short" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @param value         null-terminated value of up to 255 bytes to store, or NULL to leave alone
         * @param expiration    a new expiration timestamp, or 0 to leave alone
         * @return true iff the record exists and was updated
         *    
         * @throws IOException  raised if errors occur in the update process 
         */
        virtual bool updateString(const char* context, const char* key, const char* value=NULL, time_t expiration=0)=0;
        
        /**
         * Deletes an existing "short" record from the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @return true iff the record existed and was deleted
         *    
         * @throws IOException  raised if errors occur in the deletion process 
         */
        virtual bool deleteString(const char* context, const char* key)=0;
        
        /**
         * Creates a new "long" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @param value         null-terminated value of arbitrary length
         * @param expiration    an expiration timestamp, after which the record can be purged
         * 
         * @throws IOException  raised if errors occur in the insertion process 
         */
        virtual void createText(const char* context, const char* key, const char* value, time_t expiration)=0;
        
        /**
         * Returns an existing "long" record from the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @param pvalue        location in which to return the record value
         * @param pexpiration   location in which to return the expiration timestamp
         * @return  true iff a valid record exists and was returned   
         * 
         * @throws IOException  raised if errors occur in the read process 
         */
        virtual bool readText(const char* context, const char* key, std::string* pvalue=NULL, time_t* pexpiration=NULL)=0;

        /**
         * Updates an existing "long" record in the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
         * @param value         null-terminated value of arbitrary length to store, or NULL to leave alone
         * @param expiration    a new expiration timestamp, or 0 to leave alone
         * @return true iff the record exists and was updated
         *    
         * @throws IOException  raised if errors occur in the update process 
         */
        virtual bool updateText(const char* context, const char* key, const char* value=NULL, time_t expiration=0)=0;
        
        /**
         * Deletes an existing "long" record from the storage service.
         * 
         * @param context       a storage context label
         * @param key           null-terminated unique key of up to 255 bytes
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
         * Forcibly removes all records in a given context along with any
         * associated resources devoted to maintaining the context.
         * 
         * @param context       a storage context label
         */
        virtual void deleteContext(const char* context)=0;

    protected:
        StorageService() {}
    };

    /**
     * Registers StorageService classes into the runtime.
     */
    void XMLTOOL_API registerStorageServices();

    /** StorageService based on in-memory caching. */
    #define MEMORY_STORAGE_SERVICE  "org.opensaml.xmlooling.MemoryStorageService"
};

#endif /* __xmltooling_storage_h__ */
