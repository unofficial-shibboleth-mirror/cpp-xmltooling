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
 * @file xmltooling/soap/HTTPSOAPTransport.h
 * 
 * Encapsulates HTTP SOAP transport layer.
 */

#ifndef __xmltooling_httpsoaptrans_h__
#define __xmltooling_httpsoaptrans_h__

#include <xmltooling/soap/SOAPTransport.h>
#include <string>
#include <vector>

namespace xmltooling {
    
    /**
     * Encapsulates HTTP SOAP transport layer.
     */
    class XMLTOOL_API HTTPSOAPTransport : public virtual SOAPTransport 
    {
    protected:
        HTTPSOAPTransport() {}
    public:
        virtual ~HTTPSOAPTransport() {}
        
        /**
         * Sets an outgoing HTTP request header.
         * 
         * @param name   name of header, without the colon separator
         * @param value  header value to send
         * @return  true iff the header is successfully set
         */
        virtual bool setRequestHeader(const char* name, const char* val) const=0;
        
        /**
         * Returns the values of an HTTP response header.
         * 
         * @param name  name of header, without the colon separator
         * @return  reference to array of header values
         */
        virtual const std::vector<std::string>& getResponseHeader(const char* name) const=0;
    };

};

#endif /* __xmltooling_httpsoaptrans_h__ */
