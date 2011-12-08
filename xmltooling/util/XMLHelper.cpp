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
 * XMLHelper.cpp
 * 
 * A helper class for working with W3C DOM objects. 
 */

#include "internal.h"
#include "exceptions.h"
#include "QName.h"
#include "XMLObject.h"
#include "util/XMLHelper.h"
#include "util/XMLConstants.h"

#include <boost/lambda/bind.hpp>
#include <boost/lambda/if.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmltooling;
using namespace xercesc;
using namespace boost::lambda;
using namespace boost;
using namespace std;

static const XMLCh type[]={chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };
    
bool XMLHelper::hasXSIType(const DOMElement* e)
{
    return (e && e->hasAttributeNS(xmlconstants::XSI_NS, type));
}

xmltooling::QName* XMLHelper::getXSIType(const DOMElement* e)
{
    DOMAttr* attribute = e->getAttributeNodeNS(xmlconstants::XSI_NS, type);
    if (attribute) {
        const XMLCh* attributeValue = attribute->getTextContent();
        if (attributeValue && *attributeValue) {
            int i;
            if ((i=XMLString::indexOf(attributeValue,chColon))>0) {
                XMLCh* prefix=new XMLCh[i+1];
                XMLString::subString(prefix,attributeValue,0,i);
                prefix[i]=chNull;
                xmltooling::QName* ret=new xmltooling::QName(e->lookupNamespaceURI(prefix), attributeValue + i + 1, prefix);
                delete[] prefix;
                return ret;
            }
            else {
                return new xmltooling::QName(e->lookupNamespaceURI(nullptr), attributeValue);
            }
        }
    }

    return nullptr;
}

DOMAttr* XMLHelper::getIdAttribute(const DOMElement* domElement)
{
    if(!domElement->hasAttributes()) {
        return nullptr;
    }
    
    DOMNamedNodeMap* attributes = domElement->getAttributes();
    DOMAttr* attribute;
    for(XMLSize_t i = 0; i < attributes->getLength(); ++i) {
        attribute = static_cast<DOMAttr*>(attributes->item(i));
        if(attribute->isId()) {
            return attribute;
        }
    }
    
    return nullptr;
}

const XMLObject* XMLHelper::getXMLObjectById(const XMLObject& tree, const XMLCh* id)
{
    if (XMLString::equals(id, tree.getXMLID()))
        return &tree;
    
    const XMLObject* ret;
    const list<XMLObject*>& children = tree.getOrderedChildren();
    for (list<XMLObject*>::const_iterator i = children.begin(); i != children.end(); ++i) {
        if (*i) {
            ret = getXMLObjectById(*(*i), id);
            if (ret)
                return ret;
        }
    }
    
    return nullptr;
}

XMLObject* XMLHelper::getXMLObjectById(XMLObject& tree, const XMLCh* id)
{
    if (XMLString::equals(id, tree.getXMLID()))
        return &tree;

    XMLObject* ret;
    const list<XMLObject*>& children = tree.getOrderedChildren();
    for (list<XMLObject*>::const_iterator i = children.begin(); i != children.end(); ++i) {
        if (*i) {
            ret = getXMLObjectById(*(*i), id);
            if (ret)
                return ret;
        }
    }
    
    return nullptr;
}

void XMLHelper::getNonVisiblyUsedPrefixes(const XMLObject& tree, map<xstring,xstring>& prefixes)
{
    map<xstring,xstring> child_prefixes;
    for_each(
        tree.getOrderedChildren().begin(), tree.getOrderedChildren().end(),
        if_(_1 != nullptr)[lambda::bind(&getNonVisiblyUsedPrefixes, boost::ref(*_1), boost::ref(child_prefixes))]
        );
    const set<Namespace>& nsset = tree.getNamespaces();
    for (set<Namespace>::const_iterator ns = nsset.begin(); ns != nsset.end(); ++ns) {
        // Check for xmlns:xml.
        if (XMLString::equals(ns->getNamespacePrefix(), xmlconstants::XML_PREFIX) && XMLString::equals(ns->getNamespaceURI(), xmlconstants::XML_NS))
            continue;
        switch (ns->usage()) {
            case Namespace::Indeterminate:
                break;
            case Namespace::VisiblyUsed:
            {
                // See if the prefix was noted as non-visible below.
                const XMLCh* p = ns->getNamespacePrefix() ? ns->getNamespacePrefix() : &chNull;
                map<xstring,xstring>::iterator decl = child_prefixes.find(p);
                if (decl != child_prefixes.end()) {
                    // It's declared below, see if it's the same namespace. If so, pull it from the set,
                    // otherwise leave it in the set.
                    if (decl->second == (ns->getNamespaceURI() ? ns->getNamespaceURI() : &chNull))
                        child_prefixes.erase(decl);
                }
                break;
            }
            case Namespace::NonVisiblyUsed:
                // It may already be in the map from another branch of the tree, but as long
                // as it's set to something so the parent knows about it, we're good.
                prefixes[ns->getNamespacePrefix() ? ns->getNamespacePrefix() : &chNull] = (ns->getNamespaceURI() ? ns->getNamespaceURI() : &chNull);
                break;
        }
    }

    prefixes.insert(child_prefixes.begin(), child_prefixes.end());
}

xmltooling::QName* XMLHelper::getNodeQName(const DOMNode* domNode)
{
    if (domNode)
        return new xmltooling::QName(domNode->getNamespaceURI(), domNode->getLocalName(), domNode->getPrefix());
    return nullptr; 
}

xmltooling::QName* XMLHelper::getAttributeValueAsQName(const DOMAttr* attribute)
{
    return getNodeValueAsQName(attribute);
}

xmltooling::QName* XMLHelper::getNodeValueAsQName(const DOMNode* domNode)
{
    if (!domNode)
        return nullptr;
    
    const XMLCh* value=domNode->getTextContent();
    if (!value || !*value)
        return nullptr;

    int i;
    if ((i=XMLString::indexOf(value,chColon))>0) {
        XMLCh* prefix=new XMLCh[i+1];
        XMLString::subString(prefix,value,0,i);
        prefix[i]=chNull;
        xmltooling::QName* ret=new xmltooling::QName(domNode->lookupNamespaceURI(prefix), value + i + 1, prefix);
        delete[] prefix;
        return ret;
    }
    
    return new xmltooling::QName(domNode->lookupNamespaceURI(nullptr), value);
}

bool XMLHelper::getNodeValueAsBool(const xercesc::DOMNode* domNode, bool def)
{
    if (!domNode)
        return def;
    const XMLCh* value = domNode->getNodeValue();
    if (!value || !*value)
        return def;
    if (*value == chLatin_t || *value == chDigit_1)
        return true;
    else if (*value == chLatin_f || *value == chDigit_0)
        return false;
    return def;
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

bool XMLHelper::isNodeNamed(const xercesc::DOMNode* n, const XMLCh* ns, const XMLCh* local)
{
    return (n && XMLString::equals(local,n->getLocalName()) && XMLString::equals(ns,n->getNamespaceURI()));
}

const XMLCh* XMLHelper::getTextContent(const DOMElement* e)
{
    DOMNode* child = e ? e->getFirstChild() : nullptr;
    while (child) {
        if (child->getNodeType() == DOMNode::TEXT_NODE)
            return child->getNodeValue();
        child = child->getNextSibling();
    }
    return nullptr;
}

DOMElement* XMLHelper::getFirstChildElement(const DOMNode* n, const XMLCh* localName)
{
    DOMNode* child = n ? n->getFirstChild() : nullptr;
    while (child && child->getNodeType() != DOMNode::ELEMENT_NODE)
        child = child->getNextSibling();
    if (child && localName) {
        if (!XMLString::equals(localName,child->getLocalName()))
            return getNextSiblingElement(child, localName);
    }
    return static_cast<DOMElement*>(child);
}    

DOMElement* XMLHelper::getLastChildElement(const DOMNode* n, const XMLCh* localName)
{
    DOMNode* child = n ? n->getLastChild() : nullptr;
    while (child && child->getNodeType() != DOMNode::ELEMENT_NODE)
        child = child->getPreviousSibling();
    if (child && localName) {
        if (!XMLString::equals(localName,child->getLocalName()))
            return getPreviousSiblingElement(child, localName);
    }
    return static_cast<DOMElement*>(child);
}    

DOMElement* XMLHelper::getFirstChildElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getFirstChildElement(n, localName);
    while (e && !XMLString::equals(e->getNamespaceURI(),ns))
        e = getNextSiblingElement(e, localName);
    return e;
}

DOMElement* XMLHelper::getLastChildElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getLastChildElement(n, localName);
    while (e && !XMLString::equals(e->getNamespaceURI(),ns))
        e = getPreviousSiblingElement(e, localName);
    return e;
}

DOMElement* XMLHelper::getNextSiblingElement(const DOMNode* n, const XMLCh* localName)
{
    DOMNode* sib = n ? n->getNextSibling() : nullptr;
    while (sib && sib->getNodeType() != DOMNode::ELEMENT_NODE)
        sib = sib->getNextSibling();
    if (sib && localName) {
        if (!XMLString::equals(localName,sib->getLocalName()))
            return getNextSiblingElement(sib, localName);
    }   
    return static_cast<DOMElement*>(sib);
}

DOMElement* XMLHelper::getPreviousSiblingElement(const DOMNode* n, const XMLCh* localName)
{
    DOMNode* sib = n ? n->getPreviousSibling() : nullptr;
    while (sib && sib->getNodeType() != DOMNode::ELEMENT_NODE)
        sib = sib->getPreviousSibling();
    if (sib && localName) {
        if (!XMLString::equals(localName,sib->getLocalName()))
            return getPreviousSiblingElement(sib, localName);
    }   
    return static_cast<DOMElement*>(sib);
}

DOMElement* XMLHelper::getNextSiblingElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getNextSiblingElement(n, localName);
    while (e && !XMLString::equals(e->getNamespaceURI(),ns))
        e = getNextSiblingElement(e, localName);
    return e;
}

DOMElement* XMLHelper::getPreviousSiblingElement(const DOMNode* n, const XMLCh* ns, const XMLCh* localName)
{
    DOMElement* e = getPreviousSiblingElement(n, localName);
    while (e && !XMLString::equals(e->getNamespaceURI(),ns))
        e = getPreviousSiblingElement(e, localName);
    return e;
}

string XMLHelper::getAttrString(const DOMElement* e, const char* defValue, const XMLCh* localName, const XMLCh* ns)
{
    if (e) {
        auto_ptr_char val(e->getAttributeNS(ns, localName));
        if (val.get() && *val.get())
            return val.get();
    }
    return defValue ? defValue : "";
}

int XMLHelper::getAttrInt(const DOMElement* e, int defValue, const XMLCh* localName, const XMLCh* ns)
{
    if (e) {
        const XMLCh* val = e->getAttributeNS(ns, localName);
        if (val && *val) {
            int i = XMLString::parseInt(val);
            if (i)
                return i;
        }
    }
    return defValue;
}

bool XMLHelper::getAttrBool(const DOMElement* e, bool defValue, const XMLCh* localName, const XMLCh* ns)
{
    if (e) {
        const XMLCh* val = e->getAttributeNS(ns, localName);
        if (val) {
            if (*val == chLatin_t || *val == chDigit_1)
                return true;
            if (*val == chLatin_f || *val == chDigit_0)
                return false;
        }
    }
    return defValue;
}

void XMLHelper::serialize(const DOMNode* n, std::string& buf, bool pretty)
{
    static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
    static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDash, chDigit_8, chNull };

    MemBufFormatTarget target;
    DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(impltype);

#ifdef XMLTOOLING_XERCESC_COMPLIANT_DOMLS
    DOMLSSerializer* serializer = static_cast<DOMImplementationLS*>(impl)->createLSSerializer();
    XercesJanitor<DOMLSSerializer> janitor(serializer);
    if (pretty && serializer->getDomConfig()->canSetParameter(XMLUni::fgDOMWRTFormatPrettyPrint, pretty))
        serializer->getDomConfig()->setParameter(XMLUni::fgDOMWRTFormatPrettyPrint, pretty);
    DOMLSOutput *theOutput = static_cast<DOMImplementationLS*>(impl)->createLSOutput();
    XercesJanitor<DOMLSOutput> j_theOutput(theOutput);
    theOutput->setEncoding(UTF8);
    theOutput->setByteStream(&target);
    if (!serializer->write(n, theOutput))
        throw XMLParserException("unable to serialize XML");
#else
    DOMWriter* serializer = static_cast<DOMImplementationLS*>(impl)->createDOMWriter();
    XercesJanitor<DOMWriter> janitor(serializer);
    serializer->setEncoding(UTF8);
    if (pretty && serializer->canSetFeature(XMLUni::fgDOMWRTFormatPrettyPrint, pretty))
        serializer->setFeature(XMLUni::fgDOMWRTFormatPrettyPrint, pretty);
    if (!serializer->writeNode(&target, *n))
        throw XMLParserException("unable to serialize XML");
#endif

    buf.erase();
    buf.append(reinterpret_cast<const char*>(target.getRawBuffer()),target.getLen());
}

namespace {
    class StreamFormatTarget : public XMLFormatTarget
    {
    public:
        StreamFormatTarget(std::ostream& out) : m_out(out) {}
        ~StreamFormatTarget() {}

        void writeChars(const XMLByte *const toWrite, const xsecsize_t count, XMLFormatter *const formatter) {
            m_out.write(reinterpret_cast<const char*>(toWrite),count);
        }

        void flush() {
            m_out.flush();
        }

    private:
        std::ostream& m_out;
    };
};

ostream& XMLHelper::serialize(const DOMNode* n, ostream& out, bool pretty)
{
    static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
    static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDash, chDigit_8, chNull };

    StreamFormatTarget target(out);
    DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(impltype);

#ifdef XMLTOOLING_XERCESC_COMPLIANT_DOMLS
    DOMLSSerializer* serializer = static_cast<DOMImplementationLS*>(impl)->createLSSerializer();
    XercesJanitor<DOMLSSerializer> janitor(serializer);
    if (pretty && serializer->getDomConfig()->canSetParameter(XMLUni::fgDOMWRTFormatPrettyPrint, pretty))
        serializer->getDomConfig()->setParameter(XMLUni::fgDOMWRTFormatPrettyPrint, pretty);
    DOMLSOutput *theOutput = static_cast<DOMImplementationLS*>(impl)->createLSOutput();
    XercesJanitor<DOMLSOutput> j_theOutput(theOutput);
    theOutput->setEncoding(UTF8);
    theOutput->setByteStream(&target);
    if (!serializer->write(n, theOutput))
        throw XMLParserException("unable to serialize XML");
#else
    DOMWriter* serializer=(static_cast<DOMImplementationLS*>(impl))->createDOMWriter();
    XercesJanitor<DOMWriter> janitor(serializer);
    serializer->setEncoding(UTF8);
    if (pretty && serializer->canSetFeature(XMLUni::fgDOMWRTFormatPrettyPrint, pretty))
        serializer->setFeature(XMLUni::fgDOMWRTFormatPrettyPrint, pretty);
    if (!serializer->writeNode(&target,*n))
        throw XMLParserException("unable to serialize XML");
#endif

    return out;
}

ostream& xmltooling::operator<<(ostream& ostr, const DOMNode& node)
{
    return XMLHelper::serialize(&node, ostr);
}

ostream& xmltooling::operator<<(ostream& ostr, const XMLObject& obj)
{
    return ostr << *(obj.marshall());
}
