/*
 *  Copyright 2001-2006 Internet2
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

#include <xmltooling/util/StorageService.h>

class MemoryStorageServiceTest : public CxxTest::TestSuite {
public:
    void setUp() {
    }
    
    void tearDown() {
    }

    void testMemoryService() {
        auto_ptr<StorageService> storage(
            XMLToolingConfig::getConfig().StorageServiceManager.newPlugin(MEMORY_STORAGE_SERVICE,NULL)
            );

        string data;
        TSM_ASSERT_EQUALS("Record found in storage.", 0, storage->readString("context", "foo1", &data));
        storage->createString("context", "foo1", "bar1", time(NULL) + 60);
        storage->createString("context", "foo2", "bar2", time(NULL) + 60);
        TSM_ASSERT_EQUALS("Record not found in storage.", 1, storage->readString("context", "foo1", &data));
        TSM_ASSERT_EQUALS("Record value doesn't match.", data, "bar1");
        TSM_ASSERT_EQUALS("Update failed.", 2, storage->updateString("context", "foo2", "bar1", 0, 1));
        TSM_ASSERT_EQUALS("Record not found in storage.", 2, storage->readString("context", "foo2", &data, NULL, 1));
        TSM_ASSERT_EQUALS("Record value doesn't match.", data, "bar1");
        TSM_ASSERT("Delete failed.", storage->deleteString("context", "foo2"));
        storage->reap("context");
    }
};
