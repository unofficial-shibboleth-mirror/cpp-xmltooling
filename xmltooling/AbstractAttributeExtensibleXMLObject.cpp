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
 * AbstractAttributeExtensibleXMLObject.cpp
 * 
 * Extension of AbstractDOMCachingXMLObject that implements an AttributeExtensibleXMLObject. 
 */

#include "internal.h"
#include "AbstractAttributeExtensibleXMLObject.h"

#include <algorithm>
#include <functional>

using namespace xmltooling;
using namespace std;

class _release : public unary_function<XMLCh*,void> {
public:
    void operator()(pair<QName,XMLCh*> p) const {
        XMLString::release(&(p.second));
    }
};

AbstractAttributeExtensibleXMLObject::~AbstractAttributeExtensibleXMLObject()
{
    for_each(m_attributeMap.begin(),m_attributeMap.end(),_release());
}

void AbstractAttributeExtensibleXMLObject::setAttribute(QName& qualifiedName, const XMLCh* value)
{
    map<QName,XMLCh*>::iterator i=m_attributeMap.find(qualifiedName);
    if (i!=m_attributeMap.end()) {
        releaseThisandParentDOM();
        XMLString::release(&(i->second));
        if (value) {
            i->second=XMLString::replicate(value);
        }
        else {
            m_attributeMap.erase(i);
        }
    }
    else if (value) {
        releaseThisandParentDOM();
        m_attributeMap[qualifiedName]=XMLString::replicate(value);
    }
}
