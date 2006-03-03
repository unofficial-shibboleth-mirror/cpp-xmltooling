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

#include "XMLObjectBaseTestCase.h"

#include <fstream>

class MarshallingTest : public CxxTest::TestSuite {
    QName m_qname;
public:
    MarshallingTest() : m_qname(SimpleXMLObject::NAMESPACE,SimpleXMLObject::LOCAL_NAME) {}

    void setUp() {
        XMLObjectBuilder::registerBuilder(m_qname, new SimpleXMLObjectBuilder());
        Marshaller::registerMarshaller(m_qname, new SimpleXMLObjectMarshaller());
        Unmarshaller::registerUnmarshaller(m_qname, new SimpleXMLObjectUnmarshaller());
    }

    void tearDown() {
        XMLObjectBuilder::deregisterBuilder(m_qname);
        Marshaller::deregisterMarshaller(m_qname);
        Unmarshaller::deregisterUnmarshaller(m_qname);
    }

    void testMarshallingWithAttributes() {
        TS_TRACE("testMarshallingWithAttributes");

        auto_ptr_XMLCh expected("Firefly");
        auto_ptr<SimpleXMLObject> sxObject(dynamic_cast<SimpleXMLObject*>(XMLObjectBuilder::getBuilder(m_qname)->buildObject()));
        TS_ASSERT(sxObject.get()!=NULL);
        sxObject->setId(expected.get());
        
        DOMElement* rootElement = Marshaller::getMarshaller(sxObject.get())->marshall(sxObject.get());

        string path=data_path + "SimpleXMLObjectWithAttribute.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=nonvalidatingPool->parse(fs);
        TS_ASSERT(doc!=NULL);

        TS_ASSERT(rootElement->isEqualNode(doc->getDocumentElement()));
        doc->release();
    }

    void testMarshallingWithElementContent() {
        TS_TRACE("testMarshallingWithElementContent");

        auto_ptr_XMLCh expected("Sample Content");
        auto_ptr<SimpleXMLObject> sxObject(dynamic_cast<SimpleXMLObject*>(XMLObjectBuilder::getBuilder(m_qname)->buildObject()));
        TS_ASSERT(sxObject.get()!=NULL);
        sxObject->setValue(expected.get());
        
        DOMElement* rootElement = Marshaller::getMarshaller(sxObject.get())->marshall(sxObject.get());

        string path=data_path + "SimpleXMLObjectWithContent.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=nonvalidatingPool->parse(fs);
        TS_ASSERT(doc!=NULL);

        TS_ASSERT(rootElement->isEqualNode(doc->getDocumentElement()));
        doc->release();
    }

    void testMarshallingWithChildElements() {
        TS_TRACE("testMarshallingWithChildElements");

        const XMLObjectBuilder* b=XMLObjectBuilder::getBuilder(m_qname);
        TS_ASSERT(b!=NULL);
        
        auto_ptr<SimpleXMLObject> sxObject(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        TS_ASSERT(sxObject.get()!=NULL);
        ListOf(SimpleXMLObject) kids=sxObject->getSimpleXMLObjects();
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        kids.push_back(dynamic_cast<SimpleXMLObject*>(b->buildObject()));
        
        // Test some collection stuff
        auto_ptr_XMLCh foo("Foo");
        auto_ptr_XMLCh bar("Bar");
        kids[0]->setId(foo.get());
        kids.at(2)->setValue(bar.get());
        kids.erase(kids.begin()+1);
        
        DOMElement* rootElement = Marshaller::getMarshaller(sxObject.get())->marshall(sxObject.get());

        string path=data_path + "SimpleXMLObjectWithChildren.xml";
        ifstream fs(path.c_str());
        DOMDocument* doc=nonvalidatingPool->parse(fs);
        TS_ASSERT(doc!=NULL);

        TS_ASSERT(rootElement->isEqualNode(doc->getDocumentElement()));
        doc->release();
    }

};
