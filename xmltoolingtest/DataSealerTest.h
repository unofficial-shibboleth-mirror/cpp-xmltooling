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

#include <xmltooling/exceptions.h>
#include <xmltooling/util/DataSealer.h>

class DataSealerTest : public CxxTest::TestSuite {
public:
    void setUp() {
    }
    
    void tearDown() {
    }

    void testDataSealer() {
        auto_ptr<DataSealer> sealer(new DataSealer());

        string data = "this is a test";

        string wrapped = sealer->wrap(data.c_str(), time(nullptr) + 500);
        string unwrapped = sealer->unwrap(wrapped.c_str());
            
        TSM_ASSERT_EQUALS("DataSealer output did not match.", data, unwrapped);

        wrapped = sealer->wrap(data.c_str(), time(nullptr) - 500);
        TSM_ASSERT_THROWS("DataSealer did not throw on expired data.", sealer->unwrap(wrapped.c_str()), IOException);
    }
};
