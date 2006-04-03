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
 * KeyInfoImpl.cpp
 * 
 * Implementation classes for KeyInfo schema
 */

#include "internal.h"
#include "AbstractElementProxy.h"
#include "exceptions.h"
#include "io/AbstractXMLObjectMarshaller.h"
#include "io/AbstractXMLObjectUnmarshaller.h"
#include "signature/KeyInfo.h"
#include "util/XMLHelper.h"
#include "validation/AbstractValidatingXMLObject.h"

#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace xmlsignature {
    
    class XMLTOOL_DLLLOCAL DSAKeyValueImpl : public DSAKeyValue,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~DSAKeyValueImpl() {}

        DSAKeyValueImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        DSAKeyValueImpl(const DSAKeyValueImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            init();
            if (src.getP())
                setP(src.getP()->cloneP());
            if (src.getQ())
                setQ(src.getQ()->cloneQ());
            if (src.getG())
                setG(src.getG()->cloneG());
            if (src.getY())
                setY(src.getY()->cloneY());
            if (src.getJ())
                setJ(src.getJ()->cloneJ());
            if (src.getSeed())
                setSeed(src.getSeed()->cloneSeed());
            if (src.getPgenCounter())
                setPgenCounter(src.getPgenCounter()->clonePgenCounter());
        }
        
        void init() {
            m_P=NULL;
            m_Q=NULL;
            m_G=NULL;
            m_Y=NULL;
            m_J=NULL;
            m_Seed=NULL;
            m_PgenCounter=NULL;
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_pos_P=m_children.begin();
            m_pos_Q=m_pos_P;
            ++m_pos_Q;
            m_pos_G=m_pos_Q;
            ++m_pos_G;
            m_pos_Y=m_pos_G;
            ++m_pos_Y;
            m_pos_J=m_pos_Y;
            ++m_pos_J;
            m_pos_Seed=m_pos_J;
            ++m_pos_Seed;
            m_pos_PgenCounter=m_pos_Seed;
            ++m_pos_PgenCounter;
        }
        
        IMPL_XMLOBJECT_CLONE(DSAKeyValue);
        IMPL_XMLOBJECT_CHILD(P);
        IMPL_XMLOBJECT_CHILD(Q);
        IMPL_XMLOBJECT_CHILD(G);
        IMPL_XMLOBJECT_CHILD(Y);
        IMPL_XMLOBJECT_CHILD(J);
        IMPL_XMLOBJECT_CHILD(Seed);
        IMPL_XMLOBJECT_CHILD(PgenCounter);

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILD(P,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(Q,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(G,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(Y,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(J,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(Seed,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(PgenCounter,XMLConstants::XMLSIG_NS);
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL RSAKeyValueImpl : public RSAKeyValue,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~RSAKeyValueImpl() {}

        RSAKeyValueImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        RSAKeyValueImpl(const RSAKeyValueImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            init();
            if (src.getModulus())
                setModulus(src.getModulus()->cloneModulus());
            if (src.getExponent())
                setExponent(src.getExponent()->cloneExponent());
        }
        
        void init() {
            m_Modulus=NULL;
            m_Exponent=NULL;
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_pos_Modulus=m_children.begin();
            m_pos_Exponent=m_pos_Modulus;
            ++m_pos_Exponent;
        }
        
        IMPL_XMLOBJECT_CLONE(RSAKeyValue);
        IMPL_XMLOBJECT_CHILD(Modulus);
        IMPL_XMLOBJECT_CHILD(Exponent);

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILD(Modulus,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(Exponent,XMLConstants::XMLSIG_NS);
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL KeyValueImpl : public KeyValue,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~KeyValueImpl() {}

        KeyValueImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        KeyValueImpl(const KeyValueImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            init();
            if (src.getDSAKeyValue())
                setDSAKeyValue(src.getDSAKeyValue()->cloneDSAKeyValue());
            if (src.getRSAKeyValue())
                setRSAKeyValue(src.getRSAKeyValue()->cloneRSAKeyValue());
            if (src.getXMLObject())
                setXMLObject(src.getXMLObject()->clone());
            setTextContent(src.getTextContent());
        }
        
        void init() {
            m_TextContent=NULL;
            m_DSAKeyValue=NULL;
            m_RSAKeyValue=NULL;
            m_XMLObject=NULL;
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_pos_DSAKeyValue=m_children.begin();
            m_pos_RSAKeyValue=m_pos_DSAKeyValue;
            ++m_pos_RSAKeyValue;
            m_pos_XMLObject=m_pos_RSAKeyValue;
            ++m_pos_XMLObject;
        }
        
        IMPL_XMLOBJECT_CLONE(KeyValue);
        IMPL_XMLOBJECT_CHILD(DSAKeyValue);
        IMPL_XMLOBJECT_CHILD(RSAKeyValue);
        IMPL_XMLOBJECT_CHILD(XMLObject);
        IMPL_XMLOBJECT_CONTENT(TextContent);

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILD(DSAKeyValue,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(RSAKeyValue,XMLConstants::XMLSIG_NS);
            
            // Unknown child.
            const XMLCh* nsURI=root->getNamespaceURI();
            if (!XMLString::equals(nsURI,XMLConstants::XMLSIG_NS) && nsURI && *nsURI)
                setXMLObject(childXMLObject);
            
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL TransformImpl : public Transform,
        public AbstractDOMCachingXMLObject,
        public AbstractElementProxy,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~TransformImpl() {}

        TransformImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType), m_Algorithm(NULL) {
        }
            
        TransformImpl(const TransformImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractElementProxy(src),
                    AbstractValidatingXMLObject(src), m_Algorithm(XMLString::replicate(src.m_Algorithm)) {
            for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                if (*i) {
                    XPath* x=dynamic_cast<XPath*>(*i);
                    if (x) {
                        getXPaths().push_back(x->cloneXPath());
                        continue;
                    }
                    getXMLObjects().push_back((*i)->clone());
                }
            }
        }
        
        IMPL_XMLOBJECT_CLONE(Transform);
        IMPL_XMLOBJECT_ATTRIB(Algorithm);
        IMPL_XMLOBJECT_CHILDREN(XPath,m_children.end());

    protected:
        void marshallAttributes(DOMElement* domElement) const {
            MARSHALL_XMLOBJECT_ATTRIB(Algorithm,ALGORITHM,NULL);
        }

        void marshallElementContent(DOMElement* domElement) const {
            if(getTextContent()) {
                domElement->appendChild(domElement->getOwnerDocument()->createTextNode(getTextContent()));
            }
        }

        void processElementContent(const XMLCh* elementContent) {
            setTextContent(elementContent);
        }

        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILDREN(XPath,XMLConstants::XMLSIG_NS);
            
            // Unknown child.
            const XMLCh* nsURI=root->getNamespaceURI();
            if (!XMLString::equals(nsURI,XMLConstants::XMLSIG_NS) && nsURI && *nsURI)
                getXMLObjects().push_back(childXMLObject);
            
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }

        void processAttribute(const DOMAttr* attribute) {
            PROC_XMLOBJECT_ATTRIB(Algorithm,ALGORITHM,NULL);
        }
    };

    class XMLTOOL_DLLLOCAL TransformsImpl : public Transforms,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~TransformsImpl() {}

        TransformsImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
        }
            
        TransformsImpl(const TransformsImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            VectorOf(Transform) v=getTransforms();
            for (vector<Transform*>::const_iterator i=src.m_Transforms.begin(); i!=src.m_Transforms.end(); i++) {
                if (*i) {
                    v.push_back((*i)->cloneTransform());
                }
            }
        }
        
        IMPL_XMLOBJECT_CLONE(Transforms);
        IMPL_XMLOBJECT_CHILDREN(Transform,m_children.end());

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILDREN(Transform,XMLConstants::XMLSIG_NS);
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL RetrievalMethodImpl : public RetrievalMethod,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~RetrievalMethodImpl() {}

        RetrievalMethodImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        RetrievalMethodImpl(const RetrievalMethodImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            init();
            setURI(getURI());
            setType(getType());
            if (src.getTransforms())
                setTransforms(src.getTransforms()->cloneTransforms());
        }
        
        void init() {
            m_URI=m_Type=NULL;
            m_Transforms=NULL;
            m_children.push_back(NULL);
            m_pos_Transforms=m_children.begin();
        }
        
        IMPL_XMLOBJECT_CLONE(RetrievalMethod);
        IMPL_XMLOBJECT_ATTRIB(URI);
        IMPL_XMLOBJECT_ATTRIB(Type);
        IMPL_XMLOBJECT_CHILD(Transforms);

    protected:
        void marshallAttributes(DOMElement* domElement) const {
            MARSHALL_XMLOBJECT_ATTRIB(URI,URI,NULL);
            MARSHALL_XMLOBJECT_ATTRIB(Type,TYPE,NULL);
        }

        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILD(Transforms,XMLConstants::XMLSIG_NS);
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }

        void processAttribute(const DOMAttr* attribute) {
            PROC_XMLOBJECT_ATTRIB(URI,URI,NULL);
            PROC_XMLOBJECT_ATTRIB(Type,TYPE,NULL);
        }
    };

    class XMLTOOL_DLLLOCAL X509IssuerSerialImpl : public X509IssuerSerial,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~X509IssuerSerialImpl() {}

        X509IssuerSerialImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        X509IssuerSerialImpl(const X509IssuerSerialImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            init();
            if (src.getX509IssuerName())
                setX509IssuerName(src.getX509IssuerName()->cloneX509IssuerName());
            if (src.getX509SerialNumber())
                setX509SerialNumber(src.getX509SerialNumber()->cloneX509SerialNumber());
        }
        
        void init() {
            m_X509IssuerName=NULL;
            m_X509SerialNumber=NULL;
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_pos_X509IssuerName=m_children.begin();
            m_pos_X509SerialNumber=m_pos_X509IssuerName;
            ++m_pos_X509SerialNumber;
        }
        
        IMPL_XMLOBJECT_CLONE(X509IssuerSerial);
        IMPL_XMLOBJECT_CHILD(X509IssuerName);
        IMPL_XMLOBJECT_CHILD(X509SerialNumber);

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILD(X509IssuerName,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(X509SerialNumber,XMLConstants::XMLSIG_NS);
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL X509DataImpl : public X509Data,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~X509DataImpl() {}

        X509DataImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
        }
            
        X509DataImpl(const X509DataImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                if (*i) {
                    X509Certificate* xcert=dynamic_cast<X509Certificate*>(*i);
                    if (xcert) {
                        getX509Certificates().push_back(xcert->cloneX509Certificate());
                        continue;
                    }

                    X509CRL* xcrl=dynamic_cast<X509CRL*>(*i);
                    if (xcrl) {
                        getX509CRLs().push_back(xcrl->cloneX509CRL());
                        continue;
                    }

                    X509SubjectName* xsn=dynamic_cast<X509SubjectName*>(*i);
                    if (xsn) {
                        getX509SubjectNames().push_back(xsn->cloneX509SubjectName());
                        continue;
                    }

                    X509IssuerSerial* xis=dynamic_cast<X509IssuerSerial*>(*i);
                    if (xis) {
                        getX509IssuerSerials().push_back(xis->cloneX509IssuerSerial());
                        continue;
                    }

                    X509SKI* xski=dynamic_cast<X509SKI*>(*i);
                    if (xski) {
                        getX509SKIs().push_back(xski->cloneX509SKI());
                        continue;
                    }

                    getXMLObjects().push_back((*i)->clone());
                }
            }
        }
        
        IMPL_XMLOBJECT_CLONE(X509Data);
        IMPL_XMLOBJECT_CHILDREN(X509IssuerSerial,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(X509SKI,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(X509SubjectName,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(X509Certificate,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(X509CRL,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(XMLObject,m_children.end());

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILDREN(X509IssuerSerial,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(X509SKI,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(X509SubjectName,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(X509Certificate,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(X509CRL,XMLConstants::XMLSIG_NS);
            
            // Unknown child.
            const XMLCh* nsURI=root->getNamespaceURI();
            if (!XMLString::equals(nsURI,XMLConstants::XMLSIG_NS) && nsURI && *nsURI)
                getXMLObjects().push_back(childXMLObject);
            
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL SPKIDataImpl : public SPKIData,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~SPKIDataImpl() {}

        SPKIDataImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
        }
            
        SPKIDataImpl(const SPKIDataImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            VectorOfPairs(SPKISexp,XMLObject) v=getSPKISexps();
            for (vector< pair<SPKISexp*,XMLObject*> >::const_iterator i=src.m_SPKISexps.begin(); i!=src.m_SPKISexps.end(); i++) {
                if (i->first) {
                    v.push_back(make_pair(i->first->cloneSPKISexp(),(i->second ? i->second->clone() : (XMLObject*)NULL)));
                }
            }
        }
        
        IMPL_XMLOBJECT_CLONE(SPKIData);

    private:
        vector< pair<SPKISexp*,XMLObject*> > m_SPKISexps;

    public:
        VectorOfPairs(SPKISexp,XMLObject) getSPKISexps() {
            return VectorOfPairs(SPKISexp,XMLObject)(this, m_SPKISexps, &m_children, m_children.end());
        }
        
        const vector< pair<SPKISexp*,XMLObject*> >& getSPKISexps() const {
            return m_SPKISexps;
        }
        
    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            if (XMLHelper::isNodeNamed(root,XMLConstants::XMLSIG_NS,SPKISexp::LOCAL_NAME)) {
                SPKISexp* typesafe=dynamic_cast<SPKISexp*>(childXMLObject);
                if (typesafe) {
                    getSPKISexps().push_back(make_pair(typesafe,(XMLObject*)NULL));
                    return;
                }
            }

            // Unknown child (has to be paired with the last SPKISexp processed.
            const XMLCh* nsURI=root->getNamespaceURI();
            if (!XMLString::equals(nsURI,XMLConstants::XMLSIG_NS) && nsURI && *nsURI) {
                // Update second half of pair in vector, then add to master list.
                if (m_SPKISexps.back().second==NULL) {
                    m_SPKISexps.back().second=childXMLObject;
                    m_children.push_back(childXMLObject);
                }
                else
                    throw UnmarshallingException("Extension element must follow ds:SPKISexp element.");
            }
            
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL PGPDataImpl : public PGPData,
        public AbstractDOMCachingXMLObject,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~PGPDataImpl() {}

        PGPDataImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
                : AbstractXMLObject(nsURI, localName, prefix, schemaType) {
            init();
        }
            
        PGPDataImpl(const PGPDataImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractValidatingXMLObject(src) {
            init();
            if (src.getPGPKeyID())
                setPGPKeyID(src.getPGPKeyID()->clonePGPKeyID());
            if (src.getPGPKeyPacket())
                setPGPKeyPacket(src.getPGPKeyPacket()->clonePGPKeyPacket());
            VectorOf(XMLObject) v=getXMLObjects();
            for (vector<XMLObject*>::const_iterator i=src.m_XMLObjects.begin(); i!=src.m_XMLObjects.end(); i++) {
                if (*i) {
                    v.push_back((*i)->clone());
                }
            }
        }
        
        void init() {
            m_PGPKeyID=NULL;
            m_PGPKeyPacket=NULL;
            m_children.push_back(NULL);
            m_children.push_back(NULL);
            m_pos_PGPKeyID=m_children.begin();
            m_pos_PGPKeyPacket=m_pos_PGPKeyID;
            ++m_pos_PGPKeyPacket;
        }
        
        IMPL_XMLOBJECT_CLONE(PGPData);
        IMPL_XMLOBJECT_CHILD(PGPKeyID);
        IMPL_XMLOBJECT_CHILD(PGPKeyPacket);
        IMPL_XMLOBJECT_CHILDREN(XMLObject,m_children.end());

    protected:
        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILD(PGPKeyID,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILD(PGPKeyPacket,XMLConstants::XMLSIG_NS);

            // Unknown child.
            const XMLCh* nsURI=root->getNamespaceURI();
            if (!XMLString::equals(nsURI,XMLConstants::XMLSIG_NS) && nsURI && *nsURI)
                getXMLObjects().push_back(childXMLObject);

            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }
    };

    class XMLTOOL_DLLLOCAL KeyInfoImpl : public KeyInfo,
        public AbstractDOMCachingXMLObject,
        public AbstractElementProxy,
        public AbstractValidatingXMLObject,
        public AbstractXMLObjectMarshaller,
        public AbstractXMLObjectUnmarshaller
    {
    public:
        virtual ~KeyInfoImpl() {}

        KeyInfoImpl(const XMLCh* nsURI, const XMLCh* localName, const XMLCh* prefix, const QName* schemaType)
            : AbstractXMLObject(nsURI, localName, prefix, schemaType), m_Id(NULL) {
        }
            
        KeyInfoImpl(const KeyInfoImpl& src)
                : AbstractXMLObject(src), AbstractDOMCachingXMLObject(src), AbstractElementProxy(src),
                    AbstractValidatingXMLObject(src), m_Id(XMLString::replicate(src.m_Id)) {
            for (list<XMLObject*>::const_iterator i=src.m_children.begin(); i!=src.m_children.end(); i++) {
                if (*i) {
                    X509Data* xd=dynamic_cast<X509Data*>(*i);
                    if (xd) {
                        getX509Datas().push_back(xd->cloneX509Data());
                        continue;
                    }

                    KeyName* kn=dynamic_cast<KeyName*>(*i);
                    if (kn) {
                        getKeyNames().push_back(kn->cloneKeyName());
                        continue;
                    }

                    KeyValue* kv=dynamic_cast<KeyValue*>(*i);
                    if (kv) {
                        getKeyValues().push_back(kv->cloneKeyValue());
                        continue;
                    }

                    RetrievalMethod* rm=dynamic_cast<RetrievalMethod*>(*i);
                    if (rm) {
                        getRetrievalMethods().push_back(rm->cloneRetrievalMethod());
                        continue;
                    }

                    MgmtData* md=dynamic_cast<MgmtData*>(*i);
                    if (md) {
                        getMgmtDatas().push_back(md->cloneMgmtData());
                        continue;
                    }

                    SPKIData* sd=dynamic_cast<SPKIData*>(*i);
                    if (sd) {
                        getSPKIDatas().push_back(sd->cloneSPKIData());
                        continue;
                    }

                    PGPData* pd=dynamic_cast<PGPData*>(*i);
                    if (pd) {
                        getPGPDatas().push_back(pd->clonePGPData());
                        continue;
                    }

                    getXMLObjects().push_back((*i)->clone());
                }
            }
        }
        
        IMPL_XMLOBJECT_CLONE(KeyInfo);
        IMPL_XMLOBJECT_ATTRIB(Id);
        IMPL_XMLOBJECT_CHILDREN(KeyName,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(KeyValue,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(RetrievalMethod,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(X509Data,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(MgmtData,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(SPKIData,m_children.end());
        IMPL_XMLOBJECT_CHILDREN(PGPData,m_children.end());

    protected:
        void marshallAttributes(DOMElement* domElement) const {
            MARSHALL_XMLOBJECT_ID_ATTRIB(Id,ID,NULL);
        }

        void marshallElementContent(DOMElement* domElement) const {
            if(getTextContent()) {
                domElement->appendChild(domElement->getOwnerDocument()->createTextNode(getTextContent()));
            }
        }

        void processElementContent(const XMLCh* elementContent) {
            setTextContent(elementContent);
        }

        void processChildElement(XMLObject* childXMLObject, const DOMElement* root) {
            PROC_XMLOBJECT_CHILDREN(X509Data,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(KeyName,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(KeyValue,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(RetrievalMethod,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(MgmtData,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(SPKIData,XMLConstants::XMLSIG_NS);
            PROC_XMLOBJECT_CHILDREN(PGPData,XMLConstants::XMLSIG_NS);
            
            // Unknown child.
            const XMLCh* nsURI=root->getNamespaceURI();
            if (!XMLString::equals(nsURI,XMLConstants::XMLSIG_NS) && nsURI && *nsURI)
                getXMLObjects().push_back(childXMLObject);
            
            throw UnmarshallingException("Invalid child element: $1",params(1,childXMLObject->getElementQName().toString().c_str()));
        }

        void processAttribute(const DOMAttr* attribute) {
            PROC_XMLOBJECT_ID_ATTRIB(Id,ID,NULL);
        }
    };
    
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,KeyName,Name);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,MgmtData,Data);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,Modulus,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,Exponent,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,Seed,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,PgenCounter,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,P,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,Q,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,G,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,Y,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,J,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,XPath,Expression);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,X509IssuerName,Name);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,X509SerialNumber,SerialNumber);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,X509SKI,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,X509SubjectName,Name);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,X509Certificate,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,X509CRL,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,SPKISexp,Value);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,PGPKeyID,ID);
    DECL_XMLOBJECTIMPL_SIMPLE(XMLTOOL_DLLLOCAL,PGPKeyPacket,Packet);
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

// Builder Implementations

IMPL_XMLOBJECTBUILDER(X509IssuerSerial);
IMPL_XMLOBJECTBUILDER(X509IssuerName);
IMPL_XMLOBJECTBUILDER(X509SerialNumber);
IMPL_XMLOBJECTBUILDER(X509SKI);
IMPL_XMLOBJECTBUILDER(X509SubjectName);
IMPL_XMLOBJECTBUILDER(X509Certificate);
IMPL_XMLOBJECTBUILDER(X509CRL);
IMPL_XMLOBJECTBUILDER(X509Data);
IMPL_XMLOBJECTBUILDER(XPath);
IMPL_XMLOBJECTBUILDER(Transform);
IMPL_XMLOBJECTBUILDER(Transforms);
IMPL_XMLOBJECTBUILDER(RetrievalMethod);
IMPL_XMLOBJECTBUILDER(KeyName);
IMPL_XMLOBJECTBUILDER(MgmtData);
IMPL_XMLOBJECTBUILDER(Modulus);
IMPL_XMLOBJECTBUILDER(Exponent);
IMPL_XMLOBJECTBUILDER(Seed);
IMPL_XMLOBJECTBUILDER(PgenCounter);
IMPL_XMLOBJECTBUILDER(P);
IMPL_XMLOBJECTBUILDER(Q);
IMPL_XMLOBJECTBUILDER(G);
IMPL_XMLOBJECTBUILDER(Y);
IMPL_XMLOBJECTBUILDER(J);
IMPL_XMLOBJECTBUILDER(DSAKeyValue);
IMPL_XMLOBJECTBUILDER(RSAKeyValue);
IMPL_XMLOBJECTBUILDER(KeyValue);
IMPL_XMLOBJECTBUILDER(KeyInfo);
IMPL_XMLOBJECTBUILDER(SPKISexp);
IMPL_XMLOBJECTBUILDER(SPKIData);
IMPL_XMLOBJECTBUILDER(PGPKeyID);
IMPL_XMLOBJECTBUILDER(PGPKeyPacket);
IMPL_XMLOBJECTBUILDER(PGPData);

// Unicode literals

const XMLCh KeyInfo::LOCAL_NAME[] =             UNICODE_LITERAL_7(K,e,y,I,n,f,o);
const XMLCh KeyInfo::TYPE_NAME[] =              UNICODE_LITERAL_11(K,e,y,I,n,f,o,T,y,p,e);
const XMLCh KeyInfo::ID_ATTRIB_NAME[] =         UNICODE_LITERAL_2(I,d);
const XMLCh KeyValue::LOCAL_NAME[] =            UNICODE_LITERAL_8(K,e,y,V,a,l,u,e);
const XMLCh KeyValue::TYPE_NAME[] =             UNICODE_LITERAL_12(K,e,y,V,a,l,u,e,T,y,p,e);
const XMLCh DSAKeyValue::LOCAL_NAME[] =         UNICODE_LITERAL_11(D,S,A,K,e,y,V,a,l,u,e);
const XMLCh DSAKeyValue::TYPE_NAME[] =          UNICODE_LITERAL_15(D,S,A,K,e,y,V,a,l,u,e,T,y,p,e);
const XMLCh RSAKeyValue::LOCAL_NAME[] =         UNICODE_LITERAL_11(R,S,A,K,e,y,V,a,l,u,e);
const XMLCh RSAKeyValue::TYPE_NAME[] =          UNICODE_LITERAL_15(R,S,A,K,e,y,V,a,l,u,e,T,y,p,e);
const XMLCh MgmtData::LOCAL_NAME[] =            UNICODE_LITERAL_8(M,g,m,t,D,a,t,a);
const XMLCh KeyName::LOCAL_NAME[] =             UNICODE_LITERAL_7(K,e,y,N,a,m,e);
const XMLCh Modulus::LOCAL_NAME[] =             UNICODE_LITERAL_7(M,o,d,u,l,u,s);
const XMLCh Exponent::LOCAL_NAME[] =            UNICODE_LITERAL_8(E,x,p,o,n,e,n,t);
const XMLCh Seed::LOCAL_NAME[] =                UNICODE_LITERAL_4(S,e,e,d);
const XMLCh PgenCounter::LOCAL_NAME[] =         UNICODE_LITERAL_11(P,g,e,n,C,o,u,n,t,e,r);
const XMLCh P::LOCAL_NAME[] =                   UNICODE_LITERAL_1(P);
const XMLCh Q::LOCAL_NAME[] =                   UNICODE_LITERAL_1(Q);
const XMLCh G::LOCAL_NAME[] =                   UNICODE_LITERAL_1(G);
const XMLCh Y::LOCAL_NAME[] =                   UNICODE_LITERAL_1(Y);
const XMLCh J::LOCAL_NAME[] =                   UNICODE_LITERAL_1(J);
const XMLCh XPath::LOCAL_NAME[] =               UNICODE_LITERAL_5(X,P,a,t,h);
const XMLCh Transform::LOCAL_NAME[] =           UNICODE_LITERAL_9(T,r,a,n,s,f,o,r,m);
const XMLCh Transform::TYPE_NAME[] =            UNICODE_LITERAL_13(T,r,a,n,s,f,o,r,m,T,y,p,e);
const XMLCh Transform::ALGORITHM_ATTRIB_NAME[] = UNICODE_LITERAL_9(A,l,g,o,r,i,t,h,m);
const XMLCh Transforms::LOCAL_NAME[] =          UNICODE_LITERAL_10(T,r,a,n,s,f,o,r,m,s);
const XMLCh Transforms::TYPE_NAME[] =           UNICODE_LITERAL_14(T,r,a,n,s,f,o,r,m,s,T,y,p,e);
const XMLCh RetrievalMethod::LOCAL_NAME[] =     UNICODE_LITERAL_15(R,e,t,r,i,e,v,a,l,M,e,t,h,o,d);
const XMLCh RetrievalMethod::TYPE_NAME[] =      UNICODE_LITERAL_19(R,e,t,r,i,e,v,a,l,M,e,t,h,o,d,T,y,p,e);
const XMLCh RetrievalMethod::URI_ATTRIB_NAME[] = UNICODE_LITERAL_3(U,R,I);
const XMLCh RetrievalMethod::TYPE_ATTRIB_NAME[] = UNICODE_LITERAL_4(T,y,p,e);
const XMLCh SPKISexp::LOCAL_NAME[] =            UNICODE_LITERAL_8(S,P,K,I,S,e,x,p);
const XMLCh SPKIData::LOCAL_NAME[] =            UNICODE_LITERAL_8(S,P,K,I,D,a,t,a);
const XMLCh SPKIData::TYPE_NAME[] =             UNICODE_LITERAL_12(S,P,K,I,D,a,t,a,T,y,p,e);
const XMLCh PGPKeyID::LOCAL_NAME[] =            UNICODE_LITERAL_8(P,G,P,K,e,y,I,D);
const XMLCh PGPKeyPacket::LOCAL_NAME[] =        UNICODE_LITERAL_12(P,G,P,K,e,y,P,a,c,k,e,t);
const XMLCh PGPData::LOCAL_NAME[] =             UNICODE_LITERAL_7(P,G,P,D,a,t,a);
const XMLCh PGPData::TYPE_NAME[] =              UNICODE_LITERAL_11(P,G,P,D,a,t,a,T,y,p,e);

#define XCH(ch) chLatin_##ch
#define XNUM(d) chDigit_##d

const XMLCh X509Data::LOCAL_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(D), XCH(a), XCH(t), XCH(a), chNull
    };
const XMLCh X509Data::TYPE_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(D), XCH(a), XCH(t), XCH(a), XCH(T), XCH(y), XCH(p), XCH(e), chNull
    };
const XMLCh X509IssuerSerial::LOCAL_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(I), XCH(s), XCH(s), XCH(u), XCH(e), XCH(r),
    XCH(S), XCH(e), XCH(r), XCH(i), XCH(a), XCH(l), chNull
    };
const XMLCh X509IssuerSerial::TYPE_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(I), XCH(s), XCH(s), XCH(u), XCH(e), XCH(r),
    XCH(S), XCH(e), XCH(r), XCH(i), XCH(a), XCH(l), XCH(T), XCH(y), XCH(p), XCH(e), chNull
    };
const XMLCh X509IssuerName::LOCAL_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(I), XCH(s), XCH(s), XCH(u), XCH(e), XCH(r),
    XCH(N), XCH(a), XCH(m), XCH(e), chNull
    };
const XMLCh X509SerialNumber::LOCAL_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(S), XCH(e), XCH(r), XCH(i), XCH(a), XCH(l),
    XCH(N), XCH(u), XCH(m), XCH(b), XCH(e), XCH(r), chNull
    };
const XMLCh X509SKI::LOCAL_NAME[] = { XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(S), XCH(K), XCH(I), chNull };
const XMLCh X509SubjectName::LOCAL_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(S), XCH(u), XCH(b), XCH(j), XCH(e), XCH(c), XCH(t),
    XCH(N), XCH(a), XCH(m), XCH(e), chNull
    };
const XMLCh X509Certificate::LOCAL_NAME[] = {
    XCH(X), XNUM(5), XNUM(0), XNUM(9),
    XCH(C), XCH(e), XCH(r), XCH(t), XCH(i), XCH(f), XCH(i), XCH(c), XCH(a), XCH(t), XCH(e), chNull
    };
const XMLCh X509CRL::LOCAL_NAME[] = { XCH(X), XNUM(5), XNUM(0), XNUM(9), XCH(C), XCH(R), XCH(L), chNull };
    