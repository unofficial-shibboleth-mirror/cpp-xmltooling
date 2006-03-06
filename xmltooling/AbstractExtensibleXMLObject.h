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
 * @file AbstractExtensibleXMLObject.h
 * 
 * An abstract implementation of a DOM-caching ExtensibleXMLObject 
 */

#if !defined(__xmltooling_absextxmlobj_h__)
#define __xmltooling_absextxmlobj_h__

#include <xmltooling/AbstractDOMCachingXMLObject.h>
#include <xmltooling/ExtensibleXMLObject.h>

using namespace xercesc;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace xmltooling {

    /**
     * An abstract implementation of a DOM-caching ExtensibleXMLObject.
     */
    class XMLTOOL_API AbstractExtensibleXMLObject : public virtual AbstractDOMCachingXMLObject
    {
    public:
        virtual ~AbstractExtensibleXMLObject() {}
        
        /**
         * @see ExtensibleXMLObject::getTextContent()
         */
        virtual const XMLCh* getTextContent() const {
            return m_value;
        }
        
        /**
         * @see ExtensibleXMLObject::setTextContent()
         */
        virtual void setTextContent(const XMLCh* value);
        

        /**
         * @see ExtensibleXMLObject::getXMLObjects()
         */
        virtual ListOf(XMLObject) getXMLObjects();
    
     protected:
        /**
         * Constructor
         * 
         * @param namespaceURI the namespace the element is in
         * @param elementLocalName the local name of the XML element this Object represents
         * @param namespacePrefix the namespace prefix to use
         */
        AbstractExtensibleXMLObject(
            const XMLCh* namespaceURI=NULL, const XMLCh* elementLocalName=NULL, const XMLCh* namespacePrefix=NULL
            ) : AbstractDOMCachingXMLObject(namespaceURI,elementLocalName, namespacePrefix), m_value(NULL) {}

    private:
        XMLCh* m_value;
    };
    
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __xmltooling_absextxmlobj_h__ */
