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

/**
 * AbstractSimpleElement.cpp
 * 
 * Extension of AbstractXMLObject that implements simple elements.
 */

#include "internal.h"
#include "AbstractSimpleElement.h"

#include <xercesc/util/XMLChar.hpp>

using namespace xmltooling;
using xercesc::XMLString;
using xercesc::XMLChar1_0;
using namespace std;

// shared "empty" list of children for childless objects

list<XMLObject*> AbstractSimpleElement::m_no_children;

AbstractSimpleElement::AbstractSimpleElement() : m_value(nullptr)
{
}

AbstractSimpleElement::AbstractSimpleElement(const AbstractSimpleElement& src)
    : AbstractXMLObject(src), m_value(XMLString::replicate(src.m_value))
{
}

AbstractSimpleElement::~AbstractSimpleElement()
{
    XMLString::release(&m_value);
}

bool AbstractSimpleElement::hasChildren() const
{
    return false;
}

const list<XMLObject*>& AbstractSimpleElement::getOrderedChildren() const
{
    return m_no_children;
}

void AbstractSimpleElement::removeChild(XMLObject* child)
{
    throw XMLObjectException("Cannot remove child from a childless object.");
}

const XMLCh* AbstractSimpleElement::getTextContent(unsigned int position) const
{
    return (position==0) ? m_value : nullptr;
}

void AbstractSimpleElement::setTextContent(const XMLCh* value, unsigned int position)
{
    if (position > 0)
        throw XMLObjectException("Cannot set text content in simple element at position > 0.");

    // We overwrite the "one" piece of Text content if:
    //  - the new value is null
    //  - there is no existing value
    //  - the old value is all whitespace
    // If there's a non-whitespace value set, we leave it alone unless we're clearing it with a null.

    if (!value || !m_value || XMLChar1_0::isAllSpaces(m_value, XMLString::stringLen(m_value)))
        m_value=prepareForAssignment(m_value, value);
}
