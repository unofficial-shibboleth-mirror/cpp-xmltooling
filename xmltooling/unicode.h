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
 * @file unicode.h
 * 
 * Helper classes and types for manipulating Unicode
 */
 
#if !defined(__xmltooling_unicode_h__)
#define __xmltooling_unicode_h__

#include <string>
#include <xercesc/util/XMLString.hpp>
#include <xmltooling/base.h>

using namespace xercesc;

namespace xmltooling {
    
    #ifdef HAVE_GOOD_STL
        /**
         * An STL string type that supports 16-bit Unicode.
         * Most compilers support this, but various versions of gcc3 do not.
         */
        typedef std::basic_string<XMLCh> xstring;
    #endif

    /**
     * Transcodes a 16-bit Unicode string into UTF-8.
     * @param src   the 16-bit string to transcode
     * @return      a UTF-8 string allocated by the Xerces memory manager 
     */
    extern XMLTOOL_API char* toUTF8(const XMLCh* src);

    /**
     * Transcodes a UTF-8 string into 16-bit Unicode.
     * @param src   the UTF-8 string to transcode
     * @return      a 16-bit Unicode string allocated by the Xerces memory manager 
     */
    extern XMLTOOL_API XMLCh* fromUTF8(const char* src);

    /**
     * A minimal auto_ptr-like class that can copy or transcode a buffer into
     * the local code page and free the result automatically.
     * 
     * Needed because a standard auto_ptr would use delete on the resulting
     * pointer. 
     */
    class XMLTOOL_API auto_ptr_char
    {
    public:
        /**
         * Constructor transcodes a 16-bit Unicode string into the local code page (NOT UTF-8) and wraps the result.
         * @param src   the 16-bit string to transcode and wrap
         * @param trim  trims leading/trailing whitespace from the result (defaults to true) 
         */
        auto_ptr_char(const XMLCh* src, bool trim=true) : m_buf(XMLString::transcode(src)) {if (trim && m_buf) XMLString::trim(m_buf);}

        /**
         * Constructor copies a local code page (NOT UTF-8) string and wraps the result.
         * @param src   the local string to copy and wrap
         * @param trim  trims leading/trailing whitespace from the result (defaults to true) 
         */
        auto_ptr_char(const char* src, bool trim=true) : m_buf(XMLString::replicate(src)) {if (trim && m_buf) XMLString::trim(m_buf);}

        /**
         * Destructor frees the wrapped buffer using the Xerces memory manager.
         */
        ~auto_ptr_char() { XMLString::release(&m_buf); }

        /**
         * Returns the wrapped buffer.
         * @return a null-terminated local code page string
         */
        const char* get() const { return m_buf; }

        /**
         * Returns the wrapped buffer and transfers ownership of it to the caller.
         * @return a null-terminated local code page string
         */
        char* release() { char* temp=m_buf; m_buf=NULL; return temp; }

    private:    
        char* m_buf;
    MAKE_NONCOPYABLE(auto_ptr_char);
    };

    /**
     * A minimal auto_ptr-like class that can copy or transcode a buffer into
     * 16-bit Unicode and free the result automatically.
     * 
     * Needed because a standard auto_ptr would use delete on the resulting
     * pointer. 
     */
    class XMLTOOL_API auto_ptr_XMLCh
    {
    public:
        /**
         * Constructor transcodes a local code page (NOT UTF-8) string into 16-bit Unicode and wraps the result.
         * @param src   the local string to transcode and wrap
         * @param trim  trims leading/trailing whitespace from the result (defaults to true) 
         */
        auto_ptr_XMLCh(const char* src, bool trim=true) : m_buf(XMLString::transcode(src)) {if (trim && m_buf) XMLString::trim(m_buf);}

        /**
         * Constructor copies a 16-bit Unicode string and wraps the result.
         * @param src   the Unicode string to copy and wrap
         * @param trim  trims leading/trailing whitespace from the result (defaults to true) 
         */
        auto_ptr_XMLCh(const XMLCh* src, bool trim=true) : m_buf(XMLString::replicate(src)) {if (trim && m_buf) XMLString::trim(m_buf);}

        /**
         * Destructor frees the wrapped buffer using the Xerces memory manager.
         */
        ~auto_ptr_XMLCh() { XMLString::release(&m_buf); }

        /**
         * Returns the wrapped buffer.
         * @return a null-terminated Unicode string
         */
        const XMLCh* get() const { return m_buf; }
        
        /**
         * Returns the wrapped buffer and transfers ownership of it to the caller.
         * @return a null-terminated Unicode string
         */
        XMLCh* release() { XMLCh* temp=m_buf; m_buf=NULL; return temp; }

    private:
        XMLCh* m_buf;
    MAKE_NONCOPYABLE(auto_ptr_XMLCh);
    };

};

#endif /* __xmltooling_unicode_h__ */
