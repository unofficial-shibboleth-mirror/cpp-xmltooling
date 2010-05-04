/*
*  Copyright 2001-2010 Internet2
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
 * @file xmltooling/impl/UnknownElement.h
 * 
 * Basic implementation suitable for use as default for unrecognized content.
 */

#ifndef __xmltooling_unkelement_h__
#define __xmltooling_unkelement_h__

#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/exceptions.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>

#include <string>

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace xmltooling {

    /// @cond off
    class XMLTOOL_DLLLOCAL UnknownElementImpl : public AbstractSimpleElement, public AbstractDOMCachingXMLObject
    {
    public:
        UnknownElementImpl(const XMLCh* namespaceURI=nullptr, const XMLCh* elementLocalName=nullptr, const XMLCh* namespacePrefix=nullptr);
    
        virtual ~UnknownElementImpl();

        void releaseDOM() const;
        XMLObject* clone() const;
        const XMLCh* getTextContent(unsigned int position=0) const;
        void setTextContent(const XMLCh*, unsigned int position=0);

        xercesc::DOMElement* marshall(
            xercesc::DOMDocument* document=nullptr
#ifndef XMLTOOLING_NO_XMLSEC
            ,const std::vector<xmlsignature::Signature*>* sigs=nullptr
            ,const Credential* credential=nullptr
#endif
            ) const;

        xercesc::DOMElement* marshall(
            xercesc::DOMElement* parentElement
#ifndef XMLTOOLING_NO_XMLSEC
            ,const std::vector<xmlsignature::Signature*>* sigs=nullptr
            ,const Credential* credential=nullptr
#endif
            ) const;
        XMLObject* unmarshall(xercesc::DOMElement* element, bool bindDocument=false);
        
    protected:
        void setDocumentElement(xercesc::DOMDocument* document, xercesc::DOMElement* element) const;

        mutable std::string m_xml;

        void serialize(std::string& s) const;
    };
    /// @endcond
    
    /**
     * Builder for UnknownElementImpl objects.
     * Use as the default builder when you want unknown DOM content treated as raw/ignored XML.
     */
    class XMLTOOL_API UnknownElementBuilder : public XMLObjectBuilder
    {
    public:
        XMLObject* buildObject(
            const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=nullptr, const QName* schemaType=nullptr
            ) const;
    };

};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __xmltooling_unkelement_h__ */
