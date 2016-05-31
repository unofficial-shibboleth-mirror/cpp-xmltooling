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
#include <xercesc/framework/LocalFileInputSource.hpp>
#include <xmltooling/util/CloneInputStream.h>
#include <xmltooling/util/CurlURLInputStream.h>

extern std::string data_path;

class CloneInputStreamTest : public CxxTest::TestSuite {
public:
    void setUp() {
    }

    void tearDown() {
    }

    void testClone() {
        {
            auto_ptr_XMLCh widenitSrc((data_path + "SimpleXMLObjectWithChildren.xml").c_str());
            xercesc::LocalFileInputSource src(widenitSrc.get());
            BinInputStream* srcStream = src.makeStream();

            CloneInputStream clone(srcStream, data_path + "clonedfile.xml");
            XMLByte buffer[1024];
            XMLSize_t sz;

            do {
                sz = clone.readBytes(buffer, 1024);
            } while (sz > 0);
        }
        auto_ptr_XMLCh widenitSrc((data_path + "SimpleXMLObjectWithChildren.xml").c_str());
        LocalFileInputSource src(widenitSrc.get());
        BinInputStream* srcStream = src.makeStream(); 

        auto_ptr_XMLCh widenitDst((data_path + "clonedfile.xml").c_str());
        LocalFileInputSource dst(widenitDst.get());
        BinInputStream* dstStream = dst.makeStream(); 
        XMLSize_t sz1;
        while (true) {
            XMLByte buffer1[1024], buffer2[1024];
            XMLSize_t sz2;
            sz1 = srcStream->readBytes(buffer1, 1024);
            sz2 = dstStream->readBytes(buffer2, 1024);
            TSM_ASSERT("Size difference", sz1 == sz2);
            if (sz1 <= 0) break;
            size_t cmp = memcmp(buffer1, buffer2, sz1);
            TSM_ASSERT("Buffer difference", 0 == cmp);
        }
        delete srcStream;
        delete dstStream;
    }

};
