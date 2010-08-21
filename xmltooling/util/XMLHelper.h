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
 * @file xmltooling/util/XMLHelper.h
 *
 * A helper class for working with W3C DOM objects.
 */

#ifndef __xmltooling_xmlhelper_h__
#define __xmltooling_xmlhelper_h__

#include <xmltooling/base.h>

#include <set>
#include <iostream>
#include <xercesc/dom/DOM.hpp>

namespace xmltooling {

    class XMLTOOL_API QName;
    class XMLTOOL_API XMLObject;

    /**
     * RAII wrapper for Xerces resources.
     */
    template<class T> class XercesJanitor
    {
        MAKE_NONCOPYABLE(XercesJanitor);
        T* m_held;
    public:
        /**
         * Constructor
         *
         * @param resource  object to release when leaving scope
         */
        XercesJanitor(T* resource) : m_held(resource) {}

        ~XercesJanitor() {
            if (m_held)
                m_held->release();
        }

        /**
         * Returns resource held by this object.
         *
         * @return  the resource held or nullptr
         */
        T* get() {
            return m_held;
        }

        /**
         * Returns resource held by this object.
         *
         * @return  the resource held or nullptr
         */
        T* operator->() {
            return m_held;
        }

        /**
         * Returns resource held by this object and releases it to the caller.
         *
         * @return  the resource held or nullptr
         */
        T* release() {
            T* ret=m_held;
            m_held=nullptr;
            return ret;
        }
    };

    /**
     * A helper class for working with W3C DOM objects.
     */
    class XMLTOOL_API XMLHelper
    {
    public:
        /**
         * Checks if the given element has an xsi:type defined for it
         *
         * @param e the DOM element
         * @return true if there is a type, false if not
         */
        static bool hasXSIType(const xercesc::DOMElement* e);

        /**
         * Gets the XSI type for a given element if it has one.
         *
         * @param e the element
         * @return the type or null
         */
        static QName* getXSIType(const xercesc::DOMElement* e);

        /**
         * Gets the ID attribute of a DOM element.
         *
         * @param domElement the DOM element
         * @return the ID attribute or null if there isn't one
         */
        static xercesc::DOMAttr* getIdAttribute(const xercesc::DOMElement* domElement);

        /**
         * Attempts to locate an XMLObject from this point downward in the tree whose
         * XML ID matches the supplied value.
         *
         * @param tree  root of tree to search
         * @param id    ID value to locate
         * @return XMLObject in the tree with a matching ID value, or nullptr
         */
        static const XMLObject* getXMLObjectById(const XMLObject& tree, const XMLCh* id);

        /**
         * Attempts to locate an XMLObject from this point downward in the tree whose
         * XML ID matches the supplied value.
         *
         * @param tree  root of tree to search
         * @param id    ID value to locate
         * @return XMLObject in the tree with a matching ID value, or nullptr
         */
        static XMLObject* getXMLObjectById(XMLObject& tree, const XMLCh* id);

        /**
         * Returns the set of non-visibly-used namespace declarations found in a tree.
         * <p>Each member of the set is a prefix/URI pair.
         *
         * @param tree      root of tree to search
         * @param prefixes  container to store declarations
         */
        static void getNonVisiblyUsedPrefixes(const XMLObject& tree, std::map<xstring,xstring>& prefixes);

        /**
         * Gets the QName for the given DOM node.
         *
         * @param domNode the DOM node
         * @return the QName for the element or null if the element was null
         */
        static QName* getNodeQName(const xercesc::DOMNode* domNode);

        /**
         * @deprecated
         * Constructs a QName from an attribute's value.
         *
         * @param attribute the attribute with a QName value
         * @return a QName from an attribute's value, or null if the given attribute is null
         */
        static QName* getAttributeValueAsQName(const xercesc::DOMAttr* attribute);

        /**
         * Constructs a QName from a node's value.
         *
         * @param domNode the DOM node with a QName value
         * @return a QName from a node's value, or null if the given node has no value
         */
        static QName* getNodeValueAsQName(const xercesc::DOMNode* domNode);

        /**
         * Returns a boolean based on a node's value.
         *
         * @param domNode   the DOM node with a boolean (1/0/true/false) value
         * @param def       value to return if the node is null/missing
         * @return a bool value based on the node's value, or a default value
         */
        static bool getNodeValueAsBool(const xercesc::DOMNode* domNode, bool def);

        /**
         * Appends the child Element to the parent Element,
         * importing the child Element into the parent's Document if needed.
         *
         * @param parentElement the parent Element
         * @param childElement the child Element
         * @return the child Element that was added (may be an imported copy)
         */
        static xercesc::DOMElement* appendChildElement(xercesc::DOMElement* parentElement, xercesc::DOMElement* childElement);

        /**
         * Checks the qualified name of a node.
         *
         * @param n     node to check
         * @param ns    namespace to compare with
         * @param local local name to compare with
         * @return  true iff the node's qualified name matches the other parameters
         */
        static bool isNodeNamed(const xercesc::DOMNode* n, const XMLCh* ns, const XMLCh* local);

        /**
         * Returns the first matching child element of the node if any.
         *
         * @param n         node to check
         * @param localName local name to compare with or nullptr for any match
         * @return  the first matching child node of type Element, or nullptr
         */
        static xercesc::DOMElement* getFirstChildElement(const xercesc::DOMNode* n, const XMLCh* localName=nullptr);

        /**
         * Returns the last matching child element of the node if any.
         *
         * @param n     node to check
         * @param localName local name to compare with or nullptr for any match
         * @return  the last matching child node of type Element, or nullptr
         */
        static xercesc::DOMElement* getLastChildElement(const xercesc::DOMNode* n, const XMLCh* localName=nullptr);

        /**
         * Returns the next matching sibling element of the node if any.
         *
         * @param n     node to check
         * @param localName local name to compare with or nullptr for any match
         * @return  the next matching sibling node of type Element, or nullptr
         */
        static xercesc::DOMElement* getNextSiblingElement(const xercesc::DOMNode* n, const XMLCh* localName=nullptr);

        /**
         * Returns the previous matching sibling element of the node if any.
         *
         * @param n     node to check
         * @param localName local name to compare with or nullptr for any match
         * @return  the previous matching sibling node of type Element, or nullptr
         */
        static xercesc::DOMElement* getPreviousSiblingElement(const xercesc::DOMNode* n, const XMLCh* localName=nullptr);

        /**
         * Returns the first matching child element of the node if any.
         *
         * @param n         node to check
         * @param ns        namespace to compare with
         * @param localName local name to compare with
         * @return  the first matching child node of type Element, or nullptr
         */
        static xercesc::DOMElement* getFirstChildElement(const xercesc::DOMNode* n, const XMLCh* ns, const XMLCh* localName);

        /**
         * Returns the last matching child element of the node if any.
         *
         * @param n         node to check
         * @param ns        namespace to compare with
         * @param localName local name to compare with
         * @return  the last matching child node of type Element, or nullptr
         */
        static xercesc::DOMElement* getLastChildElement(const xercesc::DOMNode* n, const XMLCh* ns, const XMLCh* localName);

        /**
         * Returns the next matching sibling element of the node if any.
         *
         * @param n         node to check
         * @param ns        namespace to compare with
         * @param localName local name to compare with
         * @return  the next matching sibling node of type Element, or nullptr
         */
        static xercesc::DOMElement* getNextSiblingElement(const xercesc::DOMNode* n, const XMLCh* ns, const XMLCh* localName);

        /**
         * Returns the previous matching sibling element of the node if any.
         *
         * @param n         node to check
         * @param ns        namespace to compare with
         * @param localName local name to compare with
         * @return  the previous matching sibling node of type Element, or nullptr
         */
        static xercesc::DOMElement* getPreviousSiblingElement(const xercesc::DOMNode* n, const XMLCh* ns, const XMLCh* localName);

        /**
         * Returns the content of the first Text node found in the element, if any.
         * This is roughly similar to the DOM getTextContent function, but only
         * examines the immediate children of the element.
         *
         * @param e     element to examine
         * @return the content of the first Text node found, or nullptr
         */
        static const XMLCh* getTextContent(const xercesc::DOMElement* e);

        /**
         * Returns the content of the specified attribute node as a string,
         * or the default value, if the attribute is not present.
         *
         * @param e         element to examine (may be nullptr)
         * @param defValue  default value to return
         * @param localName local name of attribute
         * @param ns        namespace of attribute
         * @return  the specified attribute's value, or the specified default
         */
        static std::string getAttrString(
            const xercesc::DOMElement* e, const char* defValue, const XMLCh* localName, const XMLCh* ns=nullptr
            );

        /**
         * Returns the content of the specified attribute node as an integer,
         * or the default value, if the attribute is not present.
         *
         * @param e         element to examine (may be nullptr)
         * @param defValue  default value to return
         * @param localName local name of attribute
         * @param ns        namespace of attribute
         * @return  the specified attribute's value, or the specified default
         */
        static int getAttrInt(
            const xercesc::DOMElement* e, int defValue, const XMLCh* localName, const XMLCh* ns=nullptr
            );

        /**
         * Returns the content of the specified attribute node as a boolean,
         * or the default value, if the attribute is not present.
         *
         * @param e         element to examine (may be nullptr)
         * @param defValue  default value to return
         * @param localName local name of attribute
         * @param ns        namespace of attribute
         * @return  the specified attribute's value, or the specified default
         */
        static bool getAttrBool(
            const xercesc::DOMElement* e, bool defValue, const XMLCh* localName, const XMLCh* ns=nullptr
            );

        /**
         * Serializes the DOM node provided into a buffer using UTF-8 encoding and
         * the default XML serializer available. No manipulation or formatting is applied.
         *
         * @param n         node to serialize
         * @param buf       buffer to serialize element into
         * @param pretty    enable pretty printing if supported
         */
        static void serialize(const xercesc::DOMNode* n, std::string& buf, bool pretty=false);

        /**
         * Serializes the DOM node provided to a stream using UTF-8 encoding and
         * the default XML serializer available. No manipulation or formatting is applied.
         *
         * @param n         node to serialize
         * @param out       stream to serialize element into
         * @param pretty    enable pretty printing if supported
         * @return reference to output stream
         */
        static std::ostream& serialize(const xercesc::DOMNode* n, std::ostream& out, bool pretty=false);
    };

    /**
     * Serializes the DOM node provided to a stream using UTF-8 encoding and
     * the default XML serializer available. No manipulation or formatting is applied.
     *
     * @param n      node to serialize
     * @param ostr   stream to serialize element into
     * @return reference to output stream
     */
    extern XMLTOOL_API std::ostream& operator<<(std::ostream& ostr, const xercesc::DOMNode& n);

    /**
     * Marshalls and serializes the XMLObject provided to a stream using UTF-8 encoding and
     * the default XML serializer available. No manipulation or formatting is applied.
     *
     * <p>The marshaller operation takes no parameters.
     *
     * @param obj    object to serialize
     * @param ostr   stream to serialize object into
     * @return reference to output stream
     */
    extern XMLTOOL_API std::ostream& operator<<(std::ostream& ostr, const XMLObject& obj);
};

#endif /* __xmltooling_xmlhelper_h__ */
