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

#include "XMLObjectBaseTestCase.h"

#include <fstream>
#include <cxxtest/GlobalFixture.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>

//#define XMLTOOLINGTEST_LEAKCHECK

#ifdef WIN32
std::string data_path = "../xmltoolingtest/data/";
#else
std::string data_path = DATADIR;
#endif

class ToolingFixture : public CxxTest::GlobalFixture
{
public:
    bool setUpWorld() {
        XMLToolingConfig::getConfig().log_config();

        if (getenv("XMLTOOLINGTEST_DATA"))
            data_path=std::string(getenv("XMLTOOLINGTEST_DATA")) + "/";

        if (!XMLToolingConfig::getConfig().init())
            return false;
        if (!XMLToolingConfig::getConfig().init())  // should be a no-op
            return false;

        string catalog_path = data_path + "catalog.xml";
        if (!XMLToolingConfig::getConfig().getValidatingParser().loadCatalogs(catalog_path.c_str()))
            return false;
        
        return true;
    }
    bool tearDownWorld() {
        XMLToolingConfig::getConfig().term();       // should be a no-op
        XMLToolingConfig::getConfig().term();
        XMLToolingConfig::getConfig().term();       // shouldn't break anything
#if defined(_MSC_VER ) && defined(XMLTOOLINGTEST_LEAKCHECK)
       _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
       _CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDOUT );
       _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
       _CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDOUT );
       _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
       _CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDOUT );
       _CrtDumpMemoryLeaks();
#endif
        return true;
    }
    //bool setUp() { printf( "</test>" ); return true; }
    //bool tearDown() { printf( "</test>" ); return true; }
};

static ToolingFixture globalFixture;

class GlobalTest : public CxxTest::TestSuite
{
public:
    void setUp() {
        XMLObjectBuilder::registerDefaultBuilder(new UnknownElementBuilder());
    }

    void tearDown() {
        XMLObjectBuilder::deregisterDefaultBuilder();
    }

    void testUnknown() {
        string test_path = data_path + "SimpleXMLObjectWithChildren.xml";
        ifstream fs(test_path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(fs);
        TS_ASSERT(doc!=nullptr);

        string buf1;
        XMLHelper::serialize(doc->getDocumentElement(), buf1);

        const XMLObjectBuilder* b=XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);

        scoped_ptr<XMLObject> xmlObject(b->buildFromDocument(doc)); // bind document
        TS_ASSERT(xmlObject.get()!=nullptr);

        scoped_ptr<XMLObject> clonedObject(xmlObject->clone());
        TS_ASSERT(clonedObject.get()!=nullptr);

        DOMElement* rootElement=clonedObject->marshall();
        TS_ASSERT(rootElement!=nullptr);

        // should reuse DOM
        TS_ASSERT(rootElement==clonedObject->marshall());

        string buf2;
        XMLHelper::serialize(rootElement, buf2);
        TS_ASSERT_EQUALS(buf1,buf2);
    }

    void testUnknownWithDocChange() {
        string test_path = data_path + "SimpleXMLObjectWithChildren.xml";
        ifstream fs(test_path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(fs);
        TS_ASSERT(doc!=nullptr);

        string buf1;
        XMLHelper::serialize(doc->getDocumentElement(), buf1);

        const XMLObjectBuilder* b=XMLObjectBuilder::getBuilder(doc->getDocumentElement());
        TS_ASSERT(b!=nullptr);

        scoped_ptr<XMLObject> xmlObject(b->buildFromDocument(doc)); // bind document
        TS_ASSERT(xmlObject.get()!=nullptr);

        DOMDocument* newDoc=XMLToolingConfig::getConfig().getParser().newDocument();
        DOMElement* rootElement=xmlObject->marshall(newDoc);
        TS_ASSERT(rootElement!=nullptr);

        string buf2;
        XMLHelper::serialize(rootElement, buf2);
        TS_ASSERT_EQUALS(buf1,buf2);

        newDoc->release();
    }

    void testHelper() {
        string test_path = data_path + "IgnoreCase.xml";
        ifstream fs(test_path.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(fs);
        TS_ASSERT(doc!=nullptr);
        DOMElement* parent = doc->getDocumentElement();

        static const XMLCh IgnoreYes[] =   UNICODE_LITERAL_9(I,g,n,o,r,e,Y,e,s);
        static const XMLCh Test[] =   UNICODE_LITERAL_4(t,e,s,t);
        DOMElement* el = XMLHelper::getFirstChildElement(parent, Test, IgnoreYes);
        TS_ASSERT(!XMLHelper::getCaseSensitive(el, true));

        static const XMLCh IgnoreNo[] =   UNICODE_LITERAL_8(I,g,n,o,r,e,N,o);
        el = XMLHelper::getFirstChildElement(parent, Test, IgnoreNo);
        TS_ASSERT(XMLHelper::getCaseSensitive(el, false));

        static const XMLCh CaseSensitiveYes[] =   UNICODE_LITERAL_16(C,a,s,e,S,e,n,s,i,t,i,v,e,Y,e,s);
        el = XMLHelper::getFirstChildElement(parent, Test, CaseSensitiveYes);
        TS_ASSERT(XMLHelper::getCaseSensitive(el, false));

        static const XMLCh CaseSensitiveNo[] =   UNICODE_LITERAL_15(C,a,s,e,S,e,n,s,i,t,i,v,e,N,o);
        el = XMLHelper::getFirstChildElement(parent, Test, CaseSensitiveNo);
        TS_ASSERT(!XMLHelper::getCaseSensitive(el, true));

        static const XMLCh Both[] =   UNICODE_LITERAL_4(B,o,t,h);
        el = XMLHelper::getFirstChildElement(parent, Test, Both);
        TS_ASSERT(XMLHelper::getCaseSensitive(el, false));

        static const XMLCh Default[] =   UNICODE_LITERAL_7(D,e,f,a,u,l,t);
        el = XMLHelper::getFirstChildElement(parent, Test, Default);
        TS_ASSERT(!XMLHelper::getCaseSensitive(el, false));
        TS_ASSERT(XMLHelper::getCaseSensitive(el, true));

        static const std::string input("&thing>thong\"<thang");
        static const std::string output("&amp;thing&gt;thong&quot;&lt;thang");
        TS_ASSERT(output == XMLHelper::encode(input.c_str()));

    }
};

