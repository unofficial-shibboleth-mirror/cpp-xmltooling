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
 * AbstractXMLObjectMarshaller.cpp
 * 
 * A thread-safe abstract marshaller.
 */

#include "internal.h"
#include "exceptions.h"
#include "io/AbstractXMLObjectMarshaller.h"
#ifndef XMLTOOLING_NO_XMLSEC
    #include "signature/Signature.h"
#endif
#include "util/NDC.h"
#include "util/XMLConstants.h"
#include "util/XMLHelper.h"

#include <algorithm>
#include <functional>
#include <xercesc/util/XMLUniDefs.hpp>
#include <log4cpp/Category.hh>

#ifndef XMLTOOLING_NO_XMLSEC
    using namespace xmlsignature;
#endif
using namespace xmlconstants;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

#define XT_log (*static_cast<Category*>(m_log))

DOMElement* AbstractXMLObjectMarshaller::marshall(
    DOMDocument* document
#ifndef XMLTOOLING_NO_XMLSEC
    ,const std::vector<xmlsignature::Signature*>* sigs
#endif
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("marshall");
#endif

    if (XT_log.isDebugEnabled()) {
        XT_log.debug("starting to marshal %s", getElementQName().toString().c_str());
    }

    DOMElement* cachedDOM=getDOM();
    if (cachedDOM) {
        if (!document || document==cachedDOM->getOwnerDocument()) {
            XT_log.debug("XMLObject has a usable cached DOM, reusing it");
            if (document)
                setDocumentElement(cachedDOM->getOwnerDocument(),cachedDOM);
            releaseParentDOM(true);
            return cachedDOM;
        }
        
        // We have a DOM but it doesn't match the document we were given. This both sucks and blows.
        // Without an adoptNode option to maintain the child pointers, we have to either import the
        // DOM while somehow reassigning all the nested references (which amounts to a complete
        // *unmarshall* operation), or we just release the existing DOM and hope that we can get
        // it back. This depends on all objects being able to preserve their DOM at all costs.
        releaseChildrenDOM(true);
        releaseDOM();
    }
    
    // If we get here, we didn't have a usable DOM (and/or we released the one we had).
    // We may need to create our own document.
    bool bindDocument=false;
    if (!document) {
        document=DOMImplementationRegistry::getDOMImplementation(NULL)->createDocument();
        bindDocument=true;
    }
    
    XercesJanitor<DOMDocument> janitor(bindDocument ? document : NULL);

    XT_log.debug("creating root element to marshall");
    DOMElement* domElement = document->createElementNS(
        getElementQName().getNamespaceURI(), getElementQName().getLocalPart()
        );
    setDocumentElement(document, domElement);
#ifndef XMLTOOLING_NO_XMLSEC
    marshallInto(domElement, sigs);
#else
    marshallInto(domElement);
#endif
    //Recache the DOM.
    XT_log.debug("caching DOM for XMLObject (document is %sbound)", bindDocument ? "" : "not ");
    setDOM(domElement, bindDocument);
    janitor.release();  // safely transferred
    releaseParentDOM(true);

    return domElement;
}

DOMElement* AbstractXMLObjectMarshaller::marshall(
    DOMElement* parentElement
#ifndef XMLTOOLING_NO_XMLSEC
    ,const std::vector<xmlsignature::Signature*>* sigs
#endif
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("marshall");
#endif

    if (XT_log.isDebugEnabled()) {
        XT_log.debug("starting to marshalling %s", getElementQName().toString().c_str());
    }

    DOMElement* cachedDOM=getDOM();
    if (cachedDOM) {
        if (parentElement->getOwnerDocument()==cachedDOM->getOwnerDocument()) {
            XT_log.debug("XMLObject has a usable cached DOM, reusing it");
            if (parentElement!=cachedDOM->getParentNode()) {
                parentElement->appendChild(cachedDOM);
                releaseParentDOM(true);
            }
            return cachedDOM;
        }
        
        // We have a DOM but it doesn't match the document we were given. This both sucks and blows.
        // Without an adoptNode option to maintain the child pointers, we have to either import the
        // DOM while somehow reassigning all the nested references (which amounts to a complete
        // *unmarshall* operation), or we just release the existing DOM and hope that we can get
        // it back. This depends on all objects being able to preserve their DOM at all costs.
        releaseChildrenDOM(true);
        releaseDOM();
    }
    
    // If we get here, we didn't have a usable DOM (and/or we released the one we had).
    XT_log.debug("creating root element to marshall");
    DOMElement* domElement = parentElement->getOwnerDocument()->createElementNS(
        getElementQName().getNamespaceURI(), getElementQName().getLocalPart()
        );
    parentElement->appendChild(domElement);
#ifndef XMLTOOLING_NO_XMLSEC
    marshallInto(domElement, sigs);
#else
    marshallInto(domElement);
#endif

    //Recache the DOM.
    XT_log.debug("caching DOM for XMLObject");
    setDOM(domElement, false);
    releaseParentDOM(true);

    return domElement;
}

void AbstractXMLObjectMarshaller::marshallInto(
    DOMElement* targetElement
#ifndef XMLTOOLING_NO_XMLSEC
    ,const std::vector<xmlsignature::Signature*>* sigs
#endif
    ) const
{
    if (getElementQName().hasPrefix())
        targetElement->setPrefix(getElementQName().getPrefix());

    if (m_schemaLocation) {
        static const XMLCh schemaLocation[]= UNICODE_LITERAL_14(s,c,h,e,m,a,L,o,c,a,t,i,o,n);
        if (targetElement->getParentNode()==NULL || targetElement->getParentNode()->getNodeType()==DOMNode::DOCUMENT_NODE)
            targetElement->setAttributeNS(XSI_NS,schemaLocation,m_schemaLocation); 
    }

    marshallElementType(targetElement);
    marshallNamespaces(targetElement);
    marshallAttributes(targetElement);
    marshallContent(targetElement);
    
#ifndef XMLTOOLING_NO_XMLSEC
    if (sigs) {
        for_each(sigs->begin(),sigs->end(),mem_fun<void,Signature>(&Signature::sign));
    }
#endif
}

void AbstractXMLObjectMarshaller::marshallElementType(DOMElement* domElement) const
{
    const QName* type = getSchemaType();
    if (type) {
        XT_log.debug("setting xsi:type attribute for XMLObject");
        
        const XMLCh* typeLocalName = type->getLocalPart();
        if (!typeLocalName || !*typeLocalName) {
            throw MarshallingException("Schema type of XMLObject may not have an empty local name.");
        }

        static const XMLCh xsitype[] = {
            chLatin_x, chLatin_s, chLatin_i, chColon, chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull
            };
        
        XMLCh* xsivalue=const_cast<XMLCh*>(typeLocalName);
        const XMLCh* prefix=type->getPrefix();
        if (prefix && *prefix) {
            xsivalue=new XMLCh[XMLString::stringLen(typeLocalName) + XMLString::stringLen(prefix) + 2*sizeof(XMLCh)];
            *xsivalue=chNull;
            XMLString::catString(xsivalue,prefix);
            static const XMLCh colon[] = {chColon, chNull};
            XMLString::catString(xsivalue,colon);
            XMLString::catString(xsivalue,typeLocalName);
        }   
        domElement->setAttributeNS(XSI_NS, xsitype, xsivalue);
        if (xsivalue != typeLocalName)
            XMLString::release(&xsivalue);

        XT_log.debug("Adding XSI namespace to list of namespaces used by XMLObject");
        addNamespace(Namespace(XSI_NS, XSI_PREFIX));
    }
}

class _addns : public binary_function<DOMElement*,Namespace,void> {
public:
    void operator()(DOMElement* domElement, const Namespace& ns) const {
        const XMLCh* prefix=ns.getNamespacePrefix();
        const XMLCh* uri=ns.getNamespaceURI();
        
        // Check to see if the prefix is already declared properly above this node.
        if (!ns.alwaysDeclare()) {
            const XMLCh* declared=lookupNamespaceURI(domElement->getParentNode(),prefix);
            if (declared && XMLString::equals(declared,uri))
                return;
        }
            
        if (prefix && *prefix) {
            XMLCh* xmlns=new XMLCh[XMLString::stringLen(XMLNS_PREFIX) + XMLString::stringLen(prefix) + 2*sizeof(XMLCh)];
            *xmlns=chNull;
            XMLString::catString(xmlns,XMLNS_PREFIX);
            static const XMLCh colon[] = {chColon, chNull};
            XMLString::catString(xmlns,colon);
            XMLString::catString(xmlns,prefix);
            domElement->setAttributeNS(XMLNS_NS, xmlns, uri);
        }
        else {
            domElement->setAttributeNS(XMLNS_NS, XMLNS_PREFIX, uri);
        }
    }

    const XMLCh* lookupNamespaceURI(const DOMNode* n, const XMLCh* prefix) const {
        // Return NULL if no declaration in effect. The empty string signifies the null namespace.
        if (!n || n->getNodeType()!=DOMNode::ELEMENT_NODE) {
            // At the root, the default namespace is set to the null namespace.
            if (!prefix || !*prefix)
                return &chNull;
            return NULL;    // we're done
        }
        DOMNamedNodeMap* attributes = static_cast<const DOMElement*>(n)->getAttributes();
        if (!attributes)
            return lookupNamespaceURI(n->getParentNode(),prefix);   // defer to parent
        DOMNode* childNode;
        DOMAttr* attribute;
        for (XMLSize_t i=0; i<attributes->getLength(); i++) {
            childNode = attributes->item(i);
            if (childNode->getNodeType() != DOMNode::ATTRIBUTE_NODE)    // not an attribute?
                continue;
            attribute = static_cast<DOMAttr*>(childNode);
            if (!XMLString::equals(attribute->getNamespaceURI(),XMLNS_NS))
                continue;   // not a namespace declaration
            // Local name should be the prefix and the value would be the URI, except for the default namespace.
            if ((!prefix || !*prefix) && XMLString::equals(attribute->getLocalName(),XMLNS_PREFIX))
                return attribute->getNodeValue();
            else if (XMLString::equals(prefix,attribute->getLocalName()))
                return attribute->getNodeValue();
        }
        // Defer to parent.
        return lookupNamespaceURI(n->getParentNode(),prefix);
    }
};

void AbstractXMLObjectMarshaller::marshallNamespaces(DOMElement* domElement) const
{
    XT_log.debug("marshalling namespace attributes for XMLObject");
    const set<Namespace>& namespaces = getNamespaces();
    for_each(namespaces.begin(),namespaces.end(),bind1st(_addns(),domElement));
}

void AbstractXMLObjectMarshaller::marshallContent(DOMElement* domElement) const
{
    XT_log.debug("marshalling text and child elements for XMLObject");
    
    const XMLCh* val;
    unsigned int pos=0;
    const list<XMLObject*>& children=getOrderedChildren();
    for (list<XMLObject*>::const_iterator i=children.begin(); i!=children.end(); ++i, ++pos) {
        val = getTextContent(pos);
        if (val && *val)
            domElement->appendChild(domElement->getOwnerDocument()->createTextNode(val));
        if (*i)
            (*i)->marshall(domElement);
    }
    val = getTextContent(pos);
    if (val && *val)
        domElement->appendChild(domElement->getOwnerDocument()->createTextNode(val));
}
