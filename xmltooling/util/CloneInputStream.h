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
 * @file xmltooling/util/CloneInputStream.h
 *
 * InputStream that wraps an InputStream and forks data into a backup file.
 */

#if !defined(__xmltooling_cloneinstr_h__)
#define __xmltooling_cloneinstr_h__

#include <xercesc/util/BinInputStream.hpp>
#include <xmltooling/logging.h>

#include <string>
#include <fstream>

namespace xmltooling {

    class XMLTOOL_API CloneInputStream : public xercesc::BinInputStream
    {
    public :
        /**
         * Constructor.
         *
         * @param stream a stream that we will read from
         * @param backingFile the name of a file to write every byte we read, as we read it.
         *        we take ownership of this, arranging to delete it in our destructor.
         */
        CloneInputStream(xercesc::BinInputStream *stream, const std::string& backingFile);

        virtual ~CloneInputStream();

        virtual XMLSize_t readBytes(XMLByte* const toFill, const XMLSize_t maxToRead);
        virtual XMLFilePos curPos() const;
        virtual const XMLCh* getContentType() const;


    private :
        logging::Category& m_log;
        xercesc::BinInputStream* m_input;
        std::ofstream m_backingStream;
    };
};

#endif // __xmltooling_curlinstr_h__
