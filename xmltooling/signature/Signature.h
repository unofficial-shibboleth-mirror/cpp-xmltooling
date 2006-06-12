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
 * @file Signature.h
 * 
 * XMLObject representing XML Digital Signature, version 20020212, Signature element. 
 */

#if !defined(__xmltooling_sig_h__) && !defined(XMLTOOLING_NO_XMLSEC)
#define __xmltooling_sig_h__

#include <xmltooling/exceptions.h>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/ContentReference.h>
#include <xmltooling/validation/ValidatingXMLObject.h>
#include <xmltooling/util/XMLConstants.h>

#include <xsec/dsig/DSIGSignature.hpp>

/**
 * @namespace xmlsignature
 * Public namespace of XML Signature classes
 */
namespace xmlsignature {

    /**
     * XMLObject representing XML Digital Signature, version 20020212, Signature element.
     * The default signature settings include Exclusive c14n w/o comments, SHA-1 digests,
     * and RSA-SHA1 signing. 
     */
    class XMLTOOL_API Signature : public virtual xmltooling::ValidatingXMLObject
    {
    public:
        virtual ~Signature() {}

        /** Element local name */
        static const XMLCh LOCAL_NAME[];

        /**
         * Sets the canonicalization method for the ds:SignedInfo element
         * 
         * @param c14n  the canonicalization method
         */
        virtual void setCanonicalizationMethod(const XMLCh* c14n)=0;
        
        /**
         * Sets the signing algorithm for the signature.
         * 
         * @param sm    the signature algorithm
         */
        virtual void setSignatureAlgorithm(const XMLCh* sm)=0;

        /**
         * Sets the signing key used to create the signature.
         * 
         * @param signingKey the secret/private key used to create the signature
         */
        virtual void setSigningKey(XSECCryptoKey* signingKey)=0;

        /**
         * Sets a KeyInfo object to embed in the Signature.
         * 
         * @param keyInfo   pointer to a KeyInfo object, or NULL
         */
        virtual void setKeyInfo(KeyInfo* keyInfo)=0;

        /**
         * Gets the KeyInfo object associated with the Signature.
         * This is <strong>NOT</strong> provided for access to the
         * data associated with an unmarshalled signature. It is
         * used only in the creation of signatures. Access to data
         * for validation purposes is provided through the native
         * DSIGSignature object.
         * 
         * @return  pointer to a KeyInfo object, or NULL
         */
        virtual KeyInfo* getKeyInfo() const=0;

        /**
         * Sets the ContentReference object to the Signature to be applied
         * when the signature is created.
         * 
         * @param reference the reference to attach, or NULL 
         */
        virtual void setContentReference(ContentReference* reference)=0;

        /**
         * Gets the ContentReference object associated with the Signature.
         * This is <strong>NOT</strong> provided for access to the
         * data associated with an unmarshalled signature. It is
         * used only in the creation of signatures. Access to data
         * for validation purposes is provided through the native
         * DSIGSignature object.
         * 
         * @return  pointer to a ContentReference object, or NULL
         */
        virtual ContentReference* getContentReference() const=0;

        
        /**
         * Gets the native Apache signature object, if present.
         * 
         * @return  the native Apache signature interface
         */
        virtual DSIGSignature* getXMLSignature() const=0;

        /**
         * Compute and append the signature based on the assigned
         * ContentReference, KeyInfo, and signing key.
         */
        virtual void sign()=0;

        /**
         * Type-safe clone operation.
         * 
         * @return  copy of object
         */
        virtual Signature* cloneSignature() const=0;

    protected:
        Signature() {}
    };

    /**
     * Builder for Signature objects.
     */
    class XMLTOOL_API SignatureBuilder : public xmltooling::XMLObjectBuilder
    {
    public:
        virtual Signature* buildObject(
            const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix=NULL, const xmltooling::QName* schemaType=NULL
            ) const;
            
        /**
         * Default builder
         * 
         * @return empty Signature object
         */
        virtual Signature* buildObject() const;

        static Signature* buildSignature() {
            const SignatureBuilder* b = dynamic_cast<const SignatureBuilder*>(
                xmltooling::XMLObjectBuilder::getBuilder(
                    xmltooling::QName(xmltooling::XMLConstants::XMLSIG_NS,Signature::LOCAL_NAME)
                    )
                );
            if (b)
                return b->buildObject();
            throw xmltooling::XMLObjectException("Unable to obtain typed builder for Signature.");
        }
    };

    DECL_XMLTOOLING_EXCEPTION(SignatureException,XMLTOOL_EXCEPTIONAPI(XMLTOOL_API),xmlsignature,xmltooling::XMLSecurityException,Exceptions in signature processing);

};

#endif /* __xmltooling_sig_h__ */
