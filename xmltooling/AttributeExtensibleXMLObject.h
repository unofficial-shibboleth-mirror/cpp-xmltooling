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
 * @file xmltooling/AttributeExtensibleXMLObject.h
 * 
 * An XMLObject that supports arbitrary attributes 
 */

#ifndef __xmltooling_attrextxmlobj_h__
#define __xmltooling_attrextxmlobj_h__

#include <xmltooling/XMLObject.h>

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace xmltooling {

    /**
     * An XMLObject that supports arbitrary attributes.
     */
    class XMLTOOL_API AttributeExtensibleXMLObject : public virtual XMLObject
    {
    protected:
        AttributeExtensibleXMLObject();
        
    public:
        virtual ~AttributeExtensibleXMLObject();
        
        /**
         * Gets the value of an XML attribute of the object.
         * 
         * @param   qualifiedName   qualified name of the attribute   
         * @return the attribute value, or nullptr
         */
        virtual const XMLCh* getAttribute(const QName& qualifiedName) const=0;
        
        /**
         * Sets (or clears) an XML attribute of the object.
         * 
         * @param qualifiedName qualified name of the attribute   
         * @param value         value to set, or nullptr to clear
         * @param ID            true iff the attribute is an XML ID
         */
        virtual void setAttribute(const QName& qualifiedName, const XMLCh* value, bool ID=false)=0;

        /**
         * Sets a QName-valued XML attribute of the object.
         * 
         * @param qualifiedName qualified name of the attribute   
         * @param value         value to set
         */
        virtual void setAttribute(const QName& qualifiedName, const QName& value);

        /**
         * Gets an immutable map of the extended XML attributes of the object.
         * 
         * This set is not guaranteed to (and generally will not) include
         * attributes defined directly on the object's "type".
         */
        virtual const std::map<QName,XMLCh*>& getExtensionAttributes() const=0;
        
        /**
         * Gets an immutable list of all the ID attributes currently registered.
         * 
         * @return list of all the ID attributes currently registered
         */
        static const std::set<QName>& getRegisteredIDAttributes();
        
        /**
         * Tests whether an XML attribute is registered as an XML ID.
         * 
         * @return true iff the attribute name matches a registered XML ID attribute 
         */
        static bool isRegisteredIDAttribute(const QName& name);
    
        /**
         * Registers a new attribute as being of XML ID type.
         * 
         * @param name the qualified attribute name
         */
        static void registerIDAttribute(const QName& name);

        /**
         * Deregisters an ID attribute.
         * 
         * @param name the qualified attribute name
         */
        static void deregisterIDAttribute(const QName& name);
        
        /**
         * Deregisters all ID attributes.
         */
        static void deregisterIDAttributes();

    private:
        /** Set of attributes to treat as XML IDs. */
        static std::set<QName> m_idAttributeSet;
    };
    
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __xmltooling_attrextxmlobj_h__ */
