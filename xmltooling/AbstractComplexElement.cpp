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

/**
 * AbstractComplexElement.cpp
 * 
 * Implementation of AbstractComplexElement.
 */

#include "internal.h"
#include "AbstractComplexElement.h"

#include <algorithm>

using namespace xmltooling;

AbstractComplexElement::~AbstractComplexElement() {
    std::for_each(m_children.begin(), m_children.end(), cleanup<XMLObject>());
}

void AbstractComplexElement::removeChild(XMLObject* child)
{
    m_children.erase(std::remove(m_children.begin(), m_children.end(), child), m_children.end());
}
