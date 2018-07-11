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
#include "logging.h"
#include "exceptions.h"
#include "QName.h"
#include "XMLObject.h"
#include "util/XMLHelper.h"
#include "util/XMLConstants.h"

#include <strstream>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/if.hpp>
#include <boost/lambda/lambda.hpp>

#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <zlib.h>

using namespace xmltooling::logging;
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
    DOMAttr* attribute = e ? e->getAttributeNodeNS(xmlconstants::XSI_NS, type) : nullptr;
    if (attribute) {
        const XMLCh* attributeValue = attribute->getNodeValue();
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
    if(!domElement || !domElement->hasAttributes()) {
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
    for(list<XMLObject*>::const_iterator i = tree.getOrderedChildren().begin(); i != tree.getOrderedChildren().end(); ++i) {
        if (*i) {
            getNonVisiblyUsedPrefixes(*(*i), child_prefixes);
        }
    }
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

xmltooling::QName* XMLHelper::getNodeValueAsQName(const DOMNode* domNode)
{
    if (!domNode)
        return nullptr;
    
    const XMLCh* value = nullptr;
    XMLCh* ownedValue = nullptr;
    
    if (domNode->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
        value = domNode->getNodeValue();
    }
    else if (domNode->getNodeType() == DOMNode::ELEMENT_NODE) {
        ownedValue = getWholeTextContent(static_cast<const DOMElement*>(domNode));
        value = ownedValue;
    }

    ArrayJanitor<XMLCh> jan(ownedValue);

    if (!value || !*value)
        return nullptr;

    int i;
    if ((i=XMLString::indexOf(value,chColon))>0) {
        XMLCh* prefix=new XMLCh[i+1];
        XMLString::subString(prefix,value,0,i);
        prefix[i]=chNull;
        ArrayJanitor<XMLCh> jan2(prefix);
        const XMLCh* ns = domNode->lookupNamespaceURI(prefix);
        if (!ns) {
            auto_ptr_char temp(prefix);
            throw XMLToolingException("Namespace prefix ($1) not declared in document.", params(1, temp.get()));
        }
        return new xmltooling::QName(ns, value + i + 1, prefix);
    }
    
    return new xmltooling::QName(domNode->lookupNamespaceURI(nullptr), value);
}

bool XMLHelper::getNodeValueAsBool(const DOMNode* domNode, bool def)
{
    if (!domNode)
        return def;

    const XMLCh* value = nullptr;
    XMLCh* ownedValue = nullptr;

    if (domNode->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
        value = domNode->getNodeValue();
    }
    else if (domNode->getNodeType() == DOMNode::ELEMENT_NODE) {
        ownedValue = getWholeTextContent(static_cast<const DOMElement*>(domNode));
        value = ownedValue;
    }

    ArrayJanitor<XMLCh> jan(ownedValue);

    if (!value || !*value)
        return def;
    else if (*value == chLatin_t || *value == chDigit_1)
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

bool XMLHelper::isNodeNamed(const DOMNode* n, const XMLCh* ns, const XMLCh* local)
{
    return (n && XMLString::equals(local,n->getLocalName()) && XMLString::equals(ns,n->getNamespaceURI()));
}

XMLCh* XMLHelper::getWholeTextContent(const DOMElement* e)
{
    XMLCh* buf = nullptr;
    const DOMNode* child = e ? e->getFirstChild() : nullptr;
    while (child) {
        if (child->getNodeType() == DOMNode::TEXT_NODE || child->getNodeType() == DOMNode::CDATA_SECTION_NODE) {
            if (child->getNodeValue()) {
                if (buf) {
                    XMLSize_t initialLen = buf ? XMLString::stringLen(buf) : 0;
                    XMLCh* merged = new XMLCh[initialLen + XMLString::stringLen(child->getNodeValue()) + 1];
                    XMLString::copyString(merged, buf);
                    XMLString::catString(merged + initialLen, child->getNodeValue());
                    delete[] buf;
                    buf = merged;
                }
                else {
                    buf = new XMLCh[XMLString::stringLen(child->getNodeValue()) + 1];
                    XMLString::copyString(buf, child->getNodeValue());
                }
            }
        }
        else if (child->getNodeType() != DOMNode::COMMENT_NODE) {
            break;
        }
        child = child->getNextSibling();
    }

    return buf;
}

const XMLCh* XMLHelper::getTextContent(const DOMElement* e)
{
    DOMNode* child = e ? e->getFirstChild() : nullptr;
    while (child) {
        if (child->getNodeType() == DOMNode::TEXT_NODE || child->getNodeType() == DOMNode::CDATA_SECTION_NODE)
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
            try {
                return XMLString::parseInt(val);
            }
            catch (XMLException&) {
            }
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

bool XMLHelper::getCaseSensitive(const xercesc::DOMElement* e, bool defValue, const XMLCh* ns)
{
    static const XMLCh ignoreCase[] = UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh caseSensitive[] = UNICODE_LITERAL_13(c,a,s,e,S,e,n,s,i,t,i,v,e);
    bool result = defValue;

    if (e) {
        const XMLCh* ic = e->getAttributeNS(ns, ignoreCase);
        if (ic && * ic) {
            Category::getInstance(XMLTOOLING_LOGCAT ".XMLHelper").warn("DEPRECATED: attribute \"ignoreCase\" encountered in configuration. Use \"caseSensitive\".");

            // caseInsensitive = !"ignoreCase"
            if (*ic == chLatin_t || *ic == chDigit_1)
                result = false;
            else if (*ic == chLatin_f || *ic == chDigit_0)
                result = true;
        }
        const XMLCh* ci = e->getAttributeNS(ns, caseSensitive);
        if (ci && *ci) {
            if (ic && *ic) {
                Category::getInstance(XMLTOOLING_LOGCAT ".XMLHelper").warn("Attribute \"ignoreCase\" and \"caseSensitive\" should not be used in the same element.");
            }
            if (*ci == chLatin_t || *ci == chDigit_1) {
                result =  true;
            }
            else if (*ci == chLatin_f || *ci == chDigit_0) {
                result =  false;
            }
        }
    }
    return result;
}

void XMLHelper::encode(std::ostream& os, const char* str)
{
    size_t pos;
    while (str && *str) {
        pos = strcspn(str, "\"<>&");
        if (pos > 0) {
            os.write(str, pos);
            str += pos;
        }
        else {
            switch (*str) {
            case '"':   os << "&quot;";     break;
            case '<':   os << "&lt;";       break;
            case '>':   os << "&gt;";       break;
            case '&':   os << "&amp;";      break;
            default:    os << *str;
            }
            str++;
        }
    }
}

std::string XMLHelper::encode(const char* str)
{
    ostrstream stream;

    encode(stream, str);
    stream << ends;
    return std::string(stream.str());
}

void XMLHelper::serialize(const DOMNode* n, std::string& buf, bool pretty)
{
    static const XMLCh impltype[] = { chLatin_L, chLatin_S, chNull };
    static const XMLCh UTF8[]={ chLatin_U, chLatin_T, chLatin_F, chDash, chDigit_8, chNull };

    MemBufFormatTarget target;
    DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(impltype);

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

    buf.erase();
    buf.append(reinterpret_cast<const char*>(target.getRawBuffer()),target.getLen());
}

namespace {
    class StreamFormatTarget : public XMLFormatTarget
    {
    public:
        StreamFormatTarget(std::ostream& out) : m_out(out) {}
        ~StreamFormatTarget() {}

        void writeChars(const XMLByte *const toWrite, const XMLSize_t count, XMLFormatter *const formatter) {
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

    return out;
}

ostream& xmltooling::operator<<(ostream& ostr, const DOMNode& node)
{
    return XMLHelper::serialize(&node, ostr);
}

ostream& xmltooling::operator<<(ostream& ostr, const XMLObject& obj)
{
    try {
        return ostr << *(obj.marshall());
    }
    catch (DOMException& ex) {
        auto_ptr_char msg(ex.getMessage());
        throw XMLParserException(msg.get());
    }
}

namespace {
    extern "C" {
        voidpf saml_zalloc(void* opaque, uInt items, uInt size)
        {
            return malloc(items*size);
        }

        void saml_zfree(void* opaque, voidpf addr)
        {
            free(addr);
        }
    };
};

char* XMLHelper::deflate(char* in, unsigned int in_len, unsigned int* out_len)
{
    z_stream z;
    memset(&z, 0, sizeof(z_stream));

    z.zalloc = saml_zalloc;
    z.zfree = saml_zfree;
    z.opaque = nullptr;
    z.next_in = (Bytef*)in;
    z.avail_in = in_len;
    *out_len = 0;

    int ret = deflateInit2(&z, 9, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        Category::getInstance(XMLTOOLING_LOGCAT ".XMLHelper").error("zlib deflateInit2 failed with error code (%d)", ret);
        return nullptr;
    }

    int dlen = in_len + (in_len >> 8) + 12;  /* orig_size * 1.001 + 12 */
    char* out = new char[dlen];
    z.next_out = (Bytef*)out;
    z.avail_out = dlen;

    ret = ::deflate(&z, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&z);
        Category::getInstance(XMLTOOLING_LOGCAT ".XMLHelper").error("zlib deflateInit2 failed with error code (%d)", ret);
        delete[] out;
    }

    *out_len = z.total_out;
    deflateEnd(&z);
    return out;
}

unsigned int XMLHelper::inflate(char* in, unsigned int in_len, ostream& out)
{
    z_stream z;
    memset(&z, 0, sizeof(z_stream));

    z.zalloc = saml_zalloc;
    z.zfree = saml_zfree;
    z.opaque = nullptr;
    z.next_in = (Bytef*)in;
    z.avail_in = in_len;

    int dlen = in_len << 3;  /* guess inflated size: orig_size * 8 */
    Byte* buf = new Byte[dlen];
    memset(buf, 0, dlen);
    z.next_out = buf;
    z.avail_out = dlen;

    int ret = inflateInit2(&z, -15);
    if (ret != Z_OK) {
        Category::getInstance(XMLTOOLING_LOGCAT ".XMLHelper").error("zlib inflateInit2 failed with error code (%d)", ret);
        delete[] buf;
        return 0;
    }

    size_t diff;
    int iter = 30;
    while (--iter) {  /* Make sure we can never be caught in infinite loop */
        ret = ::inflate(&z, Z_SYNC_FLUSH);
        switch (ret) {
        case Z_STREAM_END:
            diff = z.next_out - buf;
            z.next_out = buf;
            while (diff--)
                out << *(z.next_out++);
            goto done;

        case Z_OK:  /* avail_out should be 0 now. Time to dump the buffer. */
            diff = z.next_out - buf;
            z.next_out = buf;
            while (diff--)
                out << *(z.next_out++);
            memset(buf, 0, dlen);
            z.next_out = buf;
            z.avail_out = dlen;
            break;

        default:
            delete[] buf;
            inflateEnd(&z);
            Category::getInstance(XMLTOOLING_LOGCAT ".XMLHelper").error("zlib inflate failed with error code (%d)", ret);
            return 0;
        }
    }
done:
    delete[] buf;
    int out_len = z.total_out;
    inflateEnd(&z);
    return out_len;
}
