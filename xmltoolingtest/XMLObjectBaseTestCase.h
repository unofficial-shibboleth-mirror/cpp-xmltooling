/*
 *  Copyright 2001-2005 Internet2
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

#include <cxxtest/TestSuite.h>
#include <xmltooling/AbstractDOMCachingXMLObject.h>
#include <xmltooling/exceptions.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>

using namespace xmltooling;
using namespace std;

extern ParserPool* validatingPool;
extern ParserPool* nonvalidatingPool;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

class SimpleXMLObjectUnmarshaller;

class SimpleXMLObject : public AbstractDOMCachingXMLObject
{
public:
    static const XMLCh NAMESPACE[];
    static const XMLCh NAMESPACE_PREFIX[];
    static const XMLCh LOCAL_NAME[];
    static const XMLCh ID_ATTRIB_NAME[];
    
    SimpleXMLObject() : AbstractDOMCachingXMLObject(NAMESPACE, LOCAL_NAME, NAMESPACE_PREFIX), m_id(NULL), m_value(NULL) {}
    virtual ~SimpleXMLObject() {
        XMLString::release(&m_id);
        XMLString::release(&m_value);
        for_each(m_children.begin(), m_children.end(), cleanup<SimpleXMLObject>());
    }
    
    const XMLCh* getId() const { return m_id; }
    void setId(const XMLCh* id) { m_id=prepareForAssignment(m_id,id); }

    const XMLCh* getValue() const { return m_value; }
    void setValue(const XMLCh* value) { m_value=prepareForAssignment(m_value,value); }
    
    const list<SimpleXMLObject*>& getSimpleXMLObjects() const { return m_children; }
    
    bool hasChildren() const { return !m_children.empty(); }
    size_t getOrderedChildren(vector<XMLObject*>& children) const {
        children.assign(m_children.begin(),m_children.end());
        return children.size();
    }
    SimpleXMLObject* clone() const {
        SimpleXMLObject* ret=new SimpleXMLObject();
        ret->setId(m_id);
        ret->setValue(m_value);
        xmltooling::clone(m_children, ret->m_children);
        return ret;
    }

private:
    XMLCh* m_id;
    XMLCh* m_value;
    list<SimpleXMLObject*> m_children;
    
    friend class SimpleXMLObjectUnmarshaller;
};

class SimpleXMLObjectBuilder : public XMLObjectBuilder
{
public:
    XMLObject* buildObject() const {
        return new SimpleXMLObject();
    }
};

class SimpleXMLObjectMarshaller : public AbstractXMLObjectMarshaller
{
public:
    SimpleXMLObjectMarshaller() : AbstractXMLObjectMarshaller(SimpleXMLObject::NAMESPACE, SimpleXMLObject::LOCAL_NAME) {}

private:
    void marshallAttributes(const XMLObject& xmlObject, DOMElement* domElement) const {
        const SimpleXMLObject& simpleXMLObject = dynamic_cast<const SimpleXMLObject&>(xmlObject);
        
        if(simpleXMLObject.getId()) {
            domElement->setAttributeNS(NULL, SimpleXMLObject::ID_ATTRIB_NAME, simpleXMLObject.getId());
            domElement->setIdAttributeNS(NULL, SimpleXMLObject::ID_ATTRIB_NAME);
        }
    }

    void marshallElementContent(const XMLObject& xmlObject, DOMElement* domElement) const {
        const SimpleXMLObject& simpleXMLObject = dynamic_cast<const SimpleXMLObject&>(xmlObject);

        if(simpleXMLObject.getValue()) {
            domElement->setTextContent(simpleXMLObject.getValue());
        }
    }
};

class SimpleXMLObjectUnmarshaller : public AbstractXMLObjectUnmarshaller
{
public:
    SimpleXMLObjectUnmarshaller() : AbstractXMLObjectUnmarshaller(SimpleXMLObject::NAMESPACE, SimpleXMLObject::LOCAL_NAME) {}

private:
    void processChildElement(XMLObject& parentXMLObject, XMLObject* childXMLObject) const {
        SimpleXMLObject& simpleXMLObject = dynamic_cast<SimpleXMLObject&>(parentXMLObject);

        SimpleXMLObject* child = dynamic_cast<SimpleXMLObject*>(childXMLObject);
        if (child) {
            simpleXMLObject.m_children.push_back(child);
        }
        else {
            throw UnmarshallingException("Unknown child element cannot be added to parent object.");
        }
    }

    void processAttribute(XMLObject& xmlObject, const DOMAttr* attribute) const {
        SimpleXMLObject& simpleXMLObject = dynamic_cast<SimpleXMLObject&>(xmlObject);

        if (XMLString::equals(attribute->getLocalName(),SimpleXMLObject::ID_ATTRIB_NAME)) {
            simpleXMLObject.setId(attribute->getValue());
        }
    }

    void processElementContent(XMLObject& xmlObject, const XMLCh* elementContent) const {
        SimpleXMLObject& simpleXMLObject = dynamic_cast<SimpleXMLObject&>(xmlObject);
        
        simpleXMLObject.setValue(elementContent);
    }

};


#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
