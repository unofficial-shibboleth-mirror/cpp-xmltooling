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
 * XMLHelper.cpp
 * 
 * A helper class for working with W3C DOM objects. 
 */

#include "internal.h"
#include "exceptions.h"
#include "util/XMLHelper.h"
#include "util/XMLConstants.h"

#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmltooling;

static const XMLCh type[]={chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };
    
bool XMLHelper::hasXSIType(const DOMElement* e)
{
    if (e) {
        if (e->hasAttributeNS(XMLConstants::XSI_NS, type)) {
            return true;
        }
    }

    return false;
}

QName* XMLHelper::getXSIType(const DOMElement* e)
{
    DOMAttr* attribute = e->getAttributeNodeNS(XMLConstants::XSI_NS, type);
    if (attribute) {
        const XMLCh* attributeValue = attribute->getTextContent();
        if (attributeValue && *attributeValue) {
            int i;
            if ((i=XMLString::indexOf(attributeValue,chColon))>0) {
                XMLCh* prefix=new XMLCh[i+1];
                XMLString::subString(prefix,attributeValue,0,i);
                prefix[i]=chNull;
                QName* ret=new QName(e->lookupNamespaceURI(prefix), attributeValue + i + 1, prefix);
                delete[] prefix;
                return ret;
            }
            else {
                return new QName(e->lookupNamespaceURI(&chNull), attributeValue);
            }
        }
    }

    return NULL;
}

DOMAttr* XMLHelper::getIdAttribute(const DOMElement* domElement)
{
    if(!domElement->hasAttributes()) {
        return NULL;
    }
    
    DOMNamedNodeMap* attributes = domElement->getAttributes();
    DOMAttr* attribute;
    for(XMLSize_t i = 0; i < attributes->getLength(); i++) {
        attribute = static_cast<DOMAttr*>(attributes->item(i));
        if(attribute->isId()) {
            return attribute;
        }
    }
    
    return NULL;
}

QName* XMLHelper::getNodeQName(const DOMNode* domNode)
{
    if (domNode)
        return new QName(domNode->getNamespaceURI(), domNode->getLocalName(), domNode->getPrefix());
    return NULL; 
}

QName* XMLHelper::getAttributeValueAsQName(const DOMAttr* attribute)
{
    if (!attribute)
        return NULL;
    
    int i;
    const XMLCh* attributeValue=attribute->getTextContent();
    if (attributeValue && (i=XMLString::indexOf(attributeValue,chColon))>0) {
        XMLCh* prefix=new XMLCh[i+1];
        XMLString::subString(prefix,attributeValue,0,i);
        prefix[i]=chNull;
        QName* ret=new QName(attribute->lookupNamespaceURI(prefix), attributeValue + i + 1, prefix);
        delete[] prefix;
        return ret;
    }
    
    return new QName(attribute->lookupNamespaceURI(NULL), attributeValue);
}

DOMElement* XMLHelper::appendChildElement(DOMElement* parentElement, DOMElement* childElement)
{
    DOMDocument* parentDocument = parentElement->getOwnerDocument();
    if (childElement->getOwnerDocument() != parentDocument) {
        childElement = static_cast<DOMElement*>(parentDocument->importNode(childElement, true));
    }

    parentElement->appendChild(childElement);
    return childElement;
}

const XMLCh* XMLHelper::getTextContent(const DOMElement* e)
{
    DOMNode* child=e->getFirstChild();
    while (child) {
        if (child->getNodeType()==DOMNode::TEXT_NODE)
            return child->getNodeValue();
        child=child->getNextSibling();
    }
    return NULL;
}

DOMElement* XMLHelper::getFirstChildElement(const DOMNode* n)
{
    DOMNode* child = n->getFirstChild();
    while (child && child->getNodeType() != DOMNode::ELEMENT_NODE)
        child = child->getNextSibling();
    if (child)
        return static_cast<DOMElement*>(child);
    return NULL;
}    

DOMElement* XMLHelper::getLastChildElement(const DOMNode* n)
{
    DOMNode* child = n->getLastChild();
    while (child && child->getNodeType() != DOMNode::ELEMENT_NODE)
        child = child->getPreviousSibling();
    if (child)
        return static_cast<DOMElement*>(child);
    return NULL;
}    

DOMElement* XMLHelper::getFirstChildElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getFirstChildElement(n);
    while (e && !isNodeNamed(e, ns, localName))
        e = getNextSiblingElement(e);
    return e;
}

DOMElement* XMLHelper::getLastChildElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getLastChildElement(n);
    while (e && !isNodeNamed(e, ns, localName))
        e = getPreviousSiblingElement(e);
    return e;
}

DOMElement* XMLHelper::getNextSiblingElement(const DOMNode* n)
{
    DOMNode* sib = n->getNextSibling();
    while (sib && sib->getNodeType() != DOMNode::ELEMENT_NODE)
        sib = sib->getNextSibling();
    if (sib)
        return static_cast<DOMElement*>(sib);
    return NULL;
}

DOMElement* XMLHelper::getPreviousSiblingElement(const DOMNode* n)
{
    DOMNode* sib = n->getPreviousSibling();
    while (sib && sib->getNodeType() != DOMNode::ELEMENT_NODE)
        sib = sib->getPreviousSibling();
    if (sib)
        return static_cast<DOMElement*>(sib);
    return NULL;
}

DOMElement* XMLHelper::getNextSiblingElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getNextSiblingElement(n);
    while (e && !isNodeNamed(e, ns, localName))
        e = getNextSiblingElement(e);
    return e;
}

DOMElement* XMLHelper::getPreviousSiblingElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getPreviousSiblingElement(n);
    while (e && !isNodeNamed(e, ns, localName))
        e = getPreviousSiblingElement(e);
    return e;
}

void XMLHelper::serialize(const DOMElement* e, std::string& buf)
{
    static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
    static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDigit_8, chNull };
    DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(impltype);
    DOMWriter* serializer=(static_cast<DOMImplementationLS*>(impl))->createDOMWriter();
    serializer->setEncoding(UTF8);
    try {
        MemBufFormatTarget target;
        if (!serializer->writeNode(&target,*e))
            throw XMLParserException("unable to serialize XML");
        buf.erase();
        buf.append(reinterpret_cast<const char*>(target.getRawBuffer()),target.getLen());
        serializer->release();
    }
    catch (...) {
        serializer->release();
        throw;
    }
}
