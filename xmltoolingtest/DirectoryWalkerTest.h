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
#include <xmltooling/logging.h>
#include <xmltooling/util/DirectoryWalker.h>

using namespace xmltooling::logging;

static void counting_callback(const char* pathname, struct stat& stat_buf, void* data);

class DirectoryWalkerTest : public CxxTest::TestSuite {
    unsigned int m_count;
    Category& m_log;

    friend void counting_callback(const char* pathname, struct stat& stat_buf, void* data);

public:
    DirectoryWalkerTest() : m_log(Category::getInstance("DirectoryWalkerTest")) {

    }

    void setUp() {
        m_count = 0;
    }

    void testNoAccess() {
        DirectoryWalker walker(m_log, "invalid");
        walker.walk(counting_callback, this);
        TS_ASSERT_EQUALS(m_count, 0);
	}

    void testEmpty() {
        string path = data_path + "dirwalk-empty";
        DirectoryWalker walker(m_log, path.c_str());
        walker.walk(counting_callback, this);
        TS_ASSERT_EQUALS(m_count, 0);
    }

    void testShallow() {
        string path = data_path + "dirwalk";
        DirectoryWalker walker(m_log, path.c_str());
        walker.walk(counting_callback, this);
        TS_ASSERT_EQUALS(m_count, 3);
    }

    void testNested() {
        string path = data_path + "dirwalk";
        DirectoryWalker walker(m_log, path.c_str(), true);
        walker.walk(counting_callback, this);
        TS_ASSERT_EQUALS(m_count, 4);
    }

    void testPrefixed() {
        string path = data_path + "dirwalk";
        DirectoryWalker walker(m_log, path.c_str(), true);
        walker.walk(counting_callback, this, "foo");
        TS_ASSERT_EQUALS(m_count, 1);
    }

    void testSuffixed() {
        string path = data_path + "dirwalk";
        DirectoryWalker walker(m_log, path.c_str(), true);
        walker.walk(counting_callback, this, nullptr, ".txt");
        TS_ASSERT_EQUALS(m_count, 2);
    }
};

void counting_callback(const char* pathname, struct stat& stat_buf, void* data) {
    if (!strstr(pathname, ".gitkeep"))
        reinterpret_cast<DirectoryWalkerTest*>(data)->m_count++;
}
