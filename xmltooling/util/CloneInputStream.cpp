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
 * xmltooling/util/CloneInputStream.cpp
 *
 * InputStream that wraps an InputStream and forks data into a backup file.
 */

#include "internal.h"

#include <xmltooling/util/CloneInputStream.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>

using namespace xmltooling;
using namespace xercesc;
using namespace std;

CloneInputStream::CloneInputStream(BinInputStream* stream, const std::string& backingFile)
	: m_log(logging::Category::getInstance(XMLTOOLING_LOGCAT ".util.CloneInputStream"))
	, m_input(stream)
	, m_backingStream(backingFile.c_str(), ofstream::binary)
{
    if (!stream)
        throw IOException("No input stream supplied to CloneInputStream constructor.");
    m_log.debug("initialized");
}

CloneInputStream::~CloneInputStream()
{
    m_log.debug("deleted");
    m_backingStream.close();
    delete m_input;
}

XMLSize_t CloneInputStream::readBytes(XMLByte* const toFill, const XMLSize_t maxToRead)
{
    XMLSize_t bytesRead = m_input->readBytes(toFill, maxToRead);

    if (bytesRead) m_backingStream.write((char*)toFill, bytesRead);

    return bytesRead;
}

XMLFilePos CloneInputStream::curPos() const
{
    return m_input->curPos();
};

const XMLCh* CloneInputStream::getContentType() const
{
    return m_input->getContentType();
};
