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
 * exceptions.cpp
 * 
 * Exception classes
 */
 
#include "internal.h"
#include "exceptions.h"
#include "XMLToolingConfig.h"
#include "util/XMLConstants.h"
#include "util/XMLHelper.h"

#include <stdarg.h>
#include <sstream>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace xmltooling;
using namespace std;

params::params(int count,...)
{
    va_list args;
    va_start(args,count);
    while (count--)
        v.push_back(va_arg(args,char*));
    va_end(args);
}

namedparams::namedparams(int count,...)
{
    count*=2;
    va_list args;
    va_start(args,count);
    while (count--)
        v.push_back(va_arg(args,char*));
    va_end(args);
}

XMLToolingException::ExceptionFactoryMap XMLToolingException::m_factoryMap;

XMLToolingException* XMLToolingException::getInstance(const char* exceptionClass)
{
    if (exceptionClass) {
        ExceptionFactoryMap::const_iterator i=m_factoryMap.find(exceptionClass);
        if (i!=m_factoryMap.end())
            return (i->second)();
    }
    return new XMLToolingException();
}

XMLToolingException::XMLToolingException(const char* msg, const params& p)
{
    if (msg)
        m_msg=msg;
    addProperties(p);
}

XMLToolingException::XMLToolingException(const char* msg, const namedparams& p)
{
    if (msg)
        m_msg=msg;
    addProperties(p);
}

XMLToolingException::XMLToolingException(const std::string& msg, const params& p) : m_msg(msg)
{
    addProperties(p);
}

XMLToolingException::XMLToolingException(const std::string& msg, const namedparams& p) : m_msg(msg)
{
    addProperties(p);
}

void XMLToolingException::setMessage(const char* msg)
{
    if (msg)
        m_msg=msg;
    else
        m_msg.erase();
    m_processedmsg.erase();
}

inline const char* get_digit_character()
{
    static const char  s_characters[19] = 
    {
            '9'
        ,   '8'
        ,   '7'
        ,   '6'
        ,   '5'
        ,   '4'
        ,   '3'
        ,   '2'
        ,   '1'
        ,   '0'
        ,   '1'
        ,   '2'
        ,   '3'
        ,   '4'
        ,   '5'
        ,   '6'
        ,   '7'
        ,   '8'
        ,   '9'
    };
    static const char  *s_mid  =   s_characters + 9;

    return s_mid;
}

inline const char* unsigned_integer_to_string(char* buf, size_t cchBuf, int i)
{
    char* psz=buf + cchBuf - 1;     // Set psz to last char
    *psz = 0;                       // Set terminating null

    do {
        unsigned int lsd = i % 10;  // Get least significant
                                    // digit

        i /= 10;                    // Prepare for next most
                                    // significant digit

        --psz;                      // Move back

        *psz = get_digit_character()[lsd]; // Place the digit

    } while(i!=0 && psz>buf);

    return psz;
}

void XMLToolingException::addProperties(const params& p)
{
    m_processedmsg.erase();
    int i=m_params.size()+1;
    char buf[20];
    const vector<const char*>& v=p.get();
    for (vector<const char*>::const_iterator ci=v.begin(); ci!=v.end(); ci++) {
        m_params[unsigned_integer_to_string(buf,sizeof(buf),i++)] = *ci;
    }
}
        
void XMLToolingException::addProperties(const namedparams& p)
{
    m_processedmsg.erase();
    const vector<const char*>& v=p.get();
    for (vector<const char*>::const_iterator ci=v.begin(); ci!=v.end(); ci++) {
        m_params.erase(*ci);
        m_params[*ci] = *(ci+1);
        ci++;   // advance past name to value, then loop will advance it again
    }
}

const char* XMLToolingException::getProperty(unsigned int index) const
{
    char buf[20];
    map<string,string>::const_iterator i=m_params.find(unsigned_integer_to_string(buf,sizeof(buf),index));
    return (i==m_params.end()) ? NULL : i->second.c_str();
}

const char* XMLToolingException::getProperty(const char* name) const
{
    map<string,string>::const_iterator i=m_params.find(name);
    return (i==m_params.end()) ? NULL : i->second.c_str();
}

const char* XMLToolingException::getMessage() const
{
    if (!m_processedmsg.empty())
        return m_processedmsg.c_str();
    else if (m_params.empty())
        return m_msg.c_str();

    static const char* legal="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_";

    // Replace any parameters in the message.
    string::size_type i=0,start=0;
    while (start!=string::npos && start<m_msg.length() && (i=m_msg.find("$",start))!=string::npos) {
        if (i>start)
            m_processedmsg += m_msg.substr(start,i-start);  // append everything in between
        start=i+1;                                  // move start to the beginning of the token name
        i=m_msg.find_first_not_of(legal,start);     // find token delimiter
        if (i==start) {                             // append a non legal character
           m_processedmsg+=m_msg[start++];
           continue;
        }
        
        // search for token in map
        map<string,string>::const_iterator param=m_params.find(m_msg.substr(start,(i==string::npos) ? i : i-start));
        if (param!=m_params.end()) {
            m_processedmsg+=param->second;
            start=i;
        }
    }
    if (start!=string::npos && start<m_msg.length())
        m_processedmsg += m_msg.substr(start,i);    // append rest of string
    return m_processedmsg.c_str();
}

string XMLToolingException::toString() const
{
    string xml=string("<exception xmlns=\"http://www.opensaml.org/xmltooling\" type=\"") + getClassName() + "\">";
    const char* msg=getMessage();
    if (msg)
        xml=xml + "<message>" + msg + "</message>";
    for (map<string,string>::const_iterator i=m_params.begin(); i!=m_params.end(); i++) {
        xml=xml + "<param name=\"" + i->first + "\">" + i->second + "</param>";
    }
    xml+="</exception>";
    return xml;
}

XMLToolingException* XMLToolingException::fromStream(std::istream& in)
{
    static const XMLCh exception[] = { chLatin_e, chLatin_x, chLatin_c, chLatin_e, chLatin_p, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };
    static const XMLCh message[] = { chLatin_m, chLatin_e, chLatin_s, chLatin_s, chLatin_a, chLatin_g, chLatin_e, chNull };
    static const XMLCh name[] = { chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };
    static const XMLCh param[] = { chLatin_p, chLatin_a, chLatin_r, chLatin_a, chLatin_m, chNull };
    static const XMLCh type[] = { chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };

    DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
    
    // Check root element.
    const DOMElement* root=doc->getDocumentElement();
    if (!XMLHelper::isNodeNamed(root,XMLConstants::XMLTOOLING_NS,exception)) {
        doc->release();
        throw XMLToolingException("Invalid root element on serialized exception.");
    }
    
    auto_ptr_char classname(root->getAttributeNS(NULL,type));
    auto_ptr<XMLToolingException> excep(XMLToolingException::getInstance(classname.get()));
    
    DOMElement* child=XMLHelper::getFirstChildElement(root,XMLConstants::XMLTOOLING_NS,message);
    if (child && child->hasChildNodes()) {
        auto_ptr_char m(child->getFirstChild()->getNodeValue());
        excep->setMessage(m.get());
    }
    
    child=XMLHelper::getFirstChildElement(root,XMLConstants::XMLTOOLING_NS,param);
    while (child && child->hasChildNodes()) {
        auto_ptr_char n(child->getAttributeNS(NULL,name));
        char* v=toUTF8(child->getFirstChild()->getNodeValue());
        if (n.get() && v)
            excep->addProperty(n.get(), v);
        XMLString::release(&v);
        child=XMLHelper::getNextSiblingElement(root,XMLConstants::XMLTOOLING_NS,param);
    }

    doc->release();
    return excep.release();
}
        
XMLToolingException* XMLToolingException::fromString(const char* s)
{
    istringstream in(s);
    return fromStream(in);
}
