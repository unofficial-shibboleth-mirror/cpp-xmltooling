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
 * @file XMLConstants.h
 * 
 * Fundamental XML namespace constants 
 */

#if !defined(__xmltooling_xmlconstants_h__)
#define __xmltooling_xmlconstants_h__

#include <xmltooling/unicode.h>

namespace xmltooling {
    
    /**
     * XML related constants.
     */
    struct XMLTOOL_API XMLConstants
    {
        /**  XML core namespace ("http://www.w3.org/XML/1998/namespace") */
        static const XMLCh XML_NS[]; 

        /** XML namespace prefix for special xml attributes ("xml") */
        static const XMLCh XML_PREFIX[];
    
        /**  XML namespace for xmlns attributes ("http://www.w3.org/2000/xmlns/") */
        static const XMLCh XMLNS_NS[];
        
        /** XML namespace prefix for xmlns attributes ("xmlns") */
        static const XMLCh XMLNS_PREFIX[];
    
        /**  XML Schema namespace ("http://www.w3.org/2001/XMLSchema") */
        static const XMLCh XSD_NS[];
        
        /**  XML Schema QName prefix ("xs") */
        static const XMLCh XSD_PREFIX[];
    
        /**  XML Schema Instance namespace ("http://www.w3.org/2001/XMLSchema-instance") */
        static const XMLCh XSI_NS[];
        
        /**  XML Schema Instance QName prefix ("xsi") */
        static const XMLCh XSI_PREFIX[];
        
        /**  XML Signature namespace ("http://www.w3.org/2000/09/xmldsig#") */
        static const XMLCh XMLSIG_NS[];
        
        /**  XML Signature QName prefix ("ds") */
        static const XMLCh XMLSIG_PREFIX[];
        
        /**  XML Encryption namespace ("http://www.w3.org/2001/04/xmlenc#") */
        static const XMLCh XMLENC_NS[];
        
        /**  XML Encryption QName prefix ("xenc") */
        static const XMLCh XMLENC_PREFIX[];
        
        /**  SOAP 1.1 Envelope XML namespace ("http://schemas.xmlsoap.org/soap/envelope/") */
        static const XMLCh SOAP11ENV_NS[]; 

        /**  SOAP 1.1 Envelope QName prefix ("S") */
        static const XMLCh SOAP11ENV_PREFIX[];
    
        /**  XML Tooling namespace ("http://www.opensaml.org/xmltooling") */
        static const XMLCh XMLTOOLING_NS[];

        /**  XML "true" boolean constant */
        static const XMLCh XML_TRUE[];

        /**  XML "false" boolean constant */
        static const XMLCh XML_FALSE[];

        /**  XML "1" boolean constant */
        static const XMLCh XML_ONE[];

        /**  XML "0" boolean constant */
        static const XMLCh XML_ZERO[];
        
        /** Enumerations of the different values of a boolean attribute or element */
        enum xmltooling_bool_t {
            XML_BOOL_NULL,
            XML_BOOL_TRUE,
            XML_BOOL_FALSE,
            XML_BOOL_ONE,
            XML_BOOL_ZERO
        };
    };

};

#endif /* __xmltooling_xmlconstants_h__ */
