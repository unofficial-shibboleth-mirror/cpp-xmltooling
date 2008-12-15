/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * $Id$
 */

#if !defined(XERCESC_INCLUDE_GUARD_CURLURLINPUTSTREAM_HPP) && !defined(XMLTOOLING_LITE)
#define XERCESC_INCLUDE_GUARD_CURLURLINPUTSTREAM_HPP

#include <xmltooling/logging.h>
#include <xmltooling/util/ParserPool.h>

#include <sstream>

#include <xercesc/util/XMLURL.hpp>
#include <xercesc/util/XMLExceptMsgs.hpp>
#include <xercesc/util/Janitor.hpp>
#include <xercesc/util/BinInputStream.hpp>
#include <xercesc/util/XMLNetAccessor.hpp>

namespace xmltooling {

//
// This class implements the BinInputStream interface specified by the XML
// parser.
//

class XMLTOOL_API CurlURLInputStream : public xercesc::BinInputStream
{
public :
    CurlURLInputStream(const xercesc::XMLURL&  urlSource, const xercesc::XMLNetHTTPInfo* httpInfo=0);
    ~CurlURLInputStream();

#ifdef XMLTOOLING_XERCESC_64BITSAFE
    XMLFilePos
#else
    unsigned int
#endif
        curPos() const;
    xsecsize_t readBytes(XMLByte* const toFill, const xsecsize_t maxToRead);

#ifdef XMLTOOLING_XERCESC_INPUTSTREAM_HAS_CONTENTTYPE
    const XMLCh* getContentType() const {
        return NULL;
    }
#endif

private :
    // -----------------------------------------------------------------------
    //  Unimplemented constructors and operators
    // -----------------------------------------------------------------------
    CurlURLInputStream(const CurlURLInputStream&);
    CurlURLInputStream& operator=(const CurlURLInputStream&);

    static size_t staticWriteCallback(void* ptr, size_t size, size_t nmemb, void* stream);

    std::stringstream           fUnderlyingStream;
    xercesc::MemoryManager*     fMemoryManager;
    xercesc::XMLURL	            fURLSource;
    xercesc::ArrayJanitor<char> fURL;
    StreamInputSource::StreamBinInputStream* fInputStream;
    logging::Category&  m_log;

}; // CurlURLInputStream


inline
#ifdef XMLTOOLING_XERCESC_64BITSAFE
    XMLFilePos
#else
    unsigned int
#endif
CurlURLInputStream::curPos() const
{
    return fInputStream ? fInputStream->curPos() : 0;
}

};

#endif // CURLURLINPUTSTREAM_HPP
