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

#include <xercesc/util/XMLDateTime.hpp>

class DateTimeTest : public CxxTest::TestSuite {
public:
    void setUp() {
    }

    void tearDown() {
    }

    void testDateTime() {
        auto_ptr_XMLCh ts1("1970-01-31T00:00:00Z");
        XMLDateTime dt1(ts1.get());
        dt1.parseDateTime();
        TSM_ASSERT_EQUALS("Epoch for Jan 31, 1970 did not match.", dt1.getEpoch(), 2592000);

        XMLDateTime dt2(1227234172, false);
        auto_ptr_char ts2(dt2.getRawData());
        TSM_ASSERT("ISO string for Nov 21, 2008 02:22:52 did not match.", !strcmp(ts2.get(), "2008-11-21T02:22:52Z"));
    }

    void testDuration() {
        auto_ptr_XMLCh d1("P1D");
        XMLDateTime dt1(d1.get());
        dt1.parseDuration();
        TSM_ASSERT_EQUALS("Epoch for 1 day did not match.", dt1.getEpoch(true), 86400);

        auto_ptr_XMLCh d2("PT2H");
        XMLDateTime dt2(d2.get());
        dt2.parseDuration();
        TSM_ASSERT_EQUALS("Epoch for 2 hours did not match.", dt2.getEpoch(true), 7200);

        XMLDateTime dt3(28800, true);
        auto_ptr_char d3(dt3.getRawData());
        TSM_ASSERT("ISO string for 8 hours did not match.", !strcmp(d3.get(), "P0DT8H0M0S"));

        XMLDateTime dt4(-29000, true);
        auto_ptr_char d4(dt4.getRawData());
        TSM_ASSERT("ISO string for negative 8 hours did not match.", !strcmp(d4.get(), "-P0DT8H3M20S"));
    }
};
