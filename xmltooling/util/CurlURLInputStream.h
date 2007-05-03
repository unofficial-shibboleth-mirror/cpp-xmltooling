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
 * $Id: CurlURLInputStream.hpp 527149 2007-04-10 14:56:39Z amassari $
 */

#if !defined(XERCESC_INCLUDE_GUARD_CURLURLINPUTSTREAM_HPP)
#define XERCESC_INCLUDE_GUARD_CURLURLINPUTSTREAM_HPP

#include <curl/curl.h>
#include <curl/multi.h>
#include <curl/easy.h>

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

class XMLTOOL_DLLLOCAL CurlURLInputStream : public BinInputStream
{
public :
    CurlURLInputStream(const XMLURL&  urlSource, const XMLNetHTTPInfo* httpInfo=0);
    ~CurlURLInputStream();

    unsigned int curPos() const;
    unsigned int readBytes
    (
                XMLByte* const  toFill
        , const unsigned int    maxToRead
    );


private :
    // -----------------------------------------------------------------------
    //  Unimplemented constructors and operators
    // -----------------------------------------------------------------------
    CurlURLInputStream(const CurlURLInputStream&);
    CurlURLInputStream& operator=(const CurlURLInputStream&);
    
    static size_t staticWriteCallback(char *buffer,
                                      size_t size,
                                      size_t nitems,
                                      void *outstream);
    size_t writeCallback(			  char *buffer,
                                      size_t size,
                                      size_t nitems);


    // -----------------------------------------------------------------------
    //  Private data members
    //
    //  fSocket
    //      The socket representing the connection to the remote file.
    //  fBytesProcessed
    //      Its a rolling count of the number of bytes processed off this
    //      input stream.
    //  fBuffer
    //      Holds the http header, plus the first part of the actual
    //      data.  Filled at the time the stream is opened, data goes
    //      out to user in response to readBytes().
    //  fBufferPos, fBufferEnd
    //      Pointers into fBuffer, showing start and end+1 of content
    //      that readBytes must return.
    // -----------------------------------------------------------------------
	
    CURLM*				fMulti;
    CURL*				fEasy;
    
    MemoryManager*      fMemoryManager;
    
    XMLURL				fURLSource;
    ArrayJanitor<char>	fURL;
    
    unsigned long       fTotalBytesRead;
    XMLByte*			fWritePtr;
    unsigned long		fBytesRead;
    unsigned long		fBytesToRead;
    bool				fDataAvailable;
    
    // Overflow buffer for when curl writes more data to us
    // than we've asked for.
    XMLByte				fBuffer[CURL_MAX_WRITE_SIZE];
    XMLByte*			fBufferHeadPtr;
    XMLByte*			fBufferTailPtr;
    
}; // CurlURLInputStream


inline unsigned int
CurlURLInputStream::curPos() const
{
    return fTotalBytesRead;
}

};

#endif // CURLURLINPUTSTREAM_HPP

