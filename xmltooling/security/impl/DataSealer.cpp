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
 * URLEncoder.cpp
 * 
 * Interface to a URL-encoding mechanism along with a
 * default implementation. 
 */

#include "internal.h"
#include "logging.h"
#include "security/DataSealer.h"
#include "util/XMLHelper.h"

#include <sstream>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLDateTime.hpp>
#include <xsec/framework/XSECAlgorithmHandler.hpp>
#include <xsec/framework/XSECAlgorithmMapper.hpp>
#include <xsec/framework/XSECEnv.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/transformers/TXFMChain.hpp>
#include <xsec/transformers/TXFMBase64.hpp>
#include <xsec/transformers/TXFMSB.hpp>
#include <xsec/xenc/XENCEncryptionMethod.hpp>

using namespace xmltooling;
using xercesc::Base64;
using xercesc::DOMDocument;
using xercesc::Janitor;
using xercesc::XMLDateTime;
using namespace std;

namespace xmltooling {
    XMLTOOL_DLLLOCAL PluginManager<DataSealerKeyStrategy, string, const xercesc::DOMElement*>::Factory StaticDataSealerKeyStrategyFactory;
    //XMLTOOL_DLLLOCAL PluginManager<DataSealerKeyStrategy, string, const xercesc::DOMElement*>::Factory XMLDataSealerKeyStrategyFactory;
};

void XMLTOOL_API xmltooling::registerDataSealerKeyStrategies()
{
    XMLToolingConfig& conf = XMLToolingConfig::getConfig();
    conf.DataSealerKeyStrategyManager.registerFactory(STATIC_DATA_SEALER_KEY_STRATEGY, StaticDataSealerKeyStrategyFactory);
    //conf.DataSealerKeyStrategyManager.registerFactory(XML_DATA_SEALER_KEY_STRATEGY, XMLDataSealerKeyStrategyFactory);
}

DataSealerKeyStrategy::DataSealerKeyStrategy()
{
}

DataSealerKeyStrategy::~DataSealerKeyStrategy()
{
}

DataSealer::DataSealer(const DataSealerKeyStrategy* strategy) : m_strategy(strategy)
{
    if (!m_strategy)
        throw XMLSecurityException("DataSealer requires DataSealerKeyStrategy");
}

DataSealer::~DataSealer()
{
}

string DataSealer::wrap(const char* s, time_t exp) const
{
    // Get default key to use.
    pair<string,const XSECCryptoSymmetricKey*> defaultKey = m_strategy->getDefaultKey();

	const XMLCh* algorithm = nullptr;
	switch (defaultKey.second->getSymmetricKeyType()) {
		case XSECCryptoSymmetricKey::SymmetricKeyType::KEY_AES_128:
			algorithm = DSIGConstants::s_unicodeStrURIAES128_GCM;
			break;

		case XSECCryptoSymmetricKey::SymmetricKeyType::KEY_AES_192:
			algorithm = DSIGConstants::s_unicodeStrURIAES192_GCM;
			break;

		case XSECCryptoSymmetricKey::SymmetricKeyType::KEY_AES_256:
			algorithm = DSIGConstants::s_unicodeStrURIAES256_GCM;
			break;

		default:
			throw XMLSecurityException("Unknown key type.");
	}

	const XSECAlgorithmHandler* handler = XSECPlatformUtils::g_algorithmMapper->mapURIToHandler(algorithm);
	if (!handler) {
		throw XMLSecurityException("Unable to obtain algorithm handler.");
	}

#ifndef HAVE_GMTIME_R
    struct tm* ptime = gmtime(&exp);
#else
    struct tm res;
    struct tm* ptime = gmtime_r(exp, &res);
#endif
    char timebuf[32];
    strftime(timebuf, 32, "%Y-%m-%dT%H:%M:%SZ", ptime);

	// The data format of the plaintext packet is:
	//    PLAINTEXT := KEYLABEL + ':' + ISOEXPTIME + DATA
	// The plaintext is zipped, encrypted, base64'd, and prefixed with the
	// KEYLABEL and a colon on the outside, as a key hint.

    // Construct the plaintext packet.
	string sb(defaultKey.first);
	sb = sb + ':' + timebuf + s;

    // zip the plaintext packet
    unsigned int len;
    char* deflated = XMLHelper::deflate(const_cast<char*>(sb.c_str()), sb.length(), &len);
    if (!deflated || !len)
        throw IOException("Failed to deflate data.");

    // Finally we encrypt the data. We have to hack this a bit to reuse the xmlsec routines.

	DOMDocument* dummydoc = XMLToolingConfig::getConfig().getParser().newDocument();
	Janitor<DOMDocument> docjan(dummydoc);
	auto_ptr<XSECEnv> env(new XSECEnv(dummydoc));

    safeBuffer plaintext;
    plaintext.sbMemcpyIn(deflated, len);
    delete[] deflated;
    TXFMSB* sbt = new TXFMSB(dummydoc);
    sbt->setInput(plaintext, len);
    TXFMChain tx(sbt);

	safeBuffer ciphertext;
	try {
		auto_ptr<XENCEncryptionMethod> method(XENCEncryptionMethod::create(env.get(), algorithm));
		if (!handler->encryptToSafeBuffer(&tx, method.get(), defaultKey.second, dummydoc, ciphertext)) {
			throw XMLSecurityException("Data encryption failed.");
		}
	}
	catch (XSECException& ex) {
		auto_ptr_char msg(ex.getMsg());
		throw XMLSecurityException(msg.get());
	}

	defaultKey.first.append(":");
	defaultKey.first.append(ciphertext.rawCharBuffer(), ciphertext.sbRawBufferSize());
	return defaultKey.first;
}

string DataSealer::unwrap(const char* s) const
{
	// The data format of the plaintext packet is:
	//    PLAINTEXT := KEYLABEL + ':' + ISOEXPTIME + DATA
	// The plaintext is zipped, encrypted, base64'd, and prefixed with the
	// KEYLABEL and a colon on the outside, as a key hint.

	// First extract the key label up to the first colon.
	pair<string, const XSECCryptoSymmetricKey*> requiredKey = make_pair(string(), nullptr);
	const char* delim = strchr(s ? s : "", ':');
	if (delim && delim > s) {
		requiredKey.first.append(s, delim - s);
		requiredKey.second = m_strategy->getKey(requiredKey.first.c_str());
	}
	if (!requiredKey.second)
		throw IOException("Required decryption key not available.");

	const XMLCh* algorithm = nullptr;
	switch (requiredKey.second->getSymmetricKeyType()) {
	case XSECCryptoSymmetricKey::SymmetricKeyType::KEY_AES_128:
		algorithm = DSIGConstants::s_unicodeStrURIAES128_GCM;
		break;

	case XSECCryptoSymmetricKey::SymmetricKeyType::KEY_AES_192:
		algorithm = DSIGConstants::s_unicodeStrURIAES192_GCM;
		break;

	case XSECCryptoSymmetricKey::SymmetricKeyType::KEY_AES_256:
		algorithm = DSIGConstants::s_unicodeStrURIAES256_GCM;
		break;

	default:
		throw XMLSecurityException("Unknown key type.");
	}

	const XSECAlgorithmHandler* handler = XSECPlatformUtils::g_algorithmMapper->mapURIToHandler(algorithm);
	if (!handler) {
		throw XMLSecurityException("Unable to obtain algorithm handler.");
	}

	DOMDocument* dummydoc = XMLToolingConfig::getConfig().getParser().newDocument();
	Janitor<DOMDocument> docjan(dummydoc);
	auto_ptr<XSECEnv> env(new XSECEnv(dummydoc));

	safeBuffer ciphertext;
	ciphertext.sbStrcpyIn(++delim);
	TXFMSB* sbt = new TXFMSB(dummydoc);
	sbt->setInput(ciphertext, ciphertext.sbStrlen());
	TXFMChain tx(sbt);
	TXFMBase64* b64 = new TXFMBase64(dummydoc, true); // decodes
	tx.appendTxfm(b64);

	unsigned int len = 0;
	safeBuffer plaintext;
	try {
		auto_ptr<XENCEncryptionMethod> method(XENCEncryptionMethod::create(env.get(), algorithm));
		len = handler->decryptToSafeBuffer(&tx, method.get(), requiredKey.second, dummydoc, plaintext);
	}
	catch (XSECException& ex) {
		auto_ptr_char msg(ex.getMsg());
		throw XMLSecurityException(msg.get());
	}

	if (len == 0)
		throw XMLSecurityException("No decrypted data available.");

    // Now we have to inflate it.
    stringstream out;
    if (XMLHelper::inflate(const_cast<char*>(plaintext.rawCharBuffer()), len, out) == 0) {
        throw IOException("Unable to inflate wrapped data.");
    }

    string decrypted = out.str();

	// Pull off the key label to verify it.
	size_t i = decrypted.find(':');
	if (i == string::npos)
		throw IOException("Unable to verify key used to decrypt data.");
	string keyLabel = decrypted.substr(0, i);
	if (keyLabel != requiredKey.first)
		throw IOException("Embedded key label does not match key used to decrypt data.");

    string dstr = decrypted.substr(++i, 20);
    auto_ptr_XMLCh expstr(dstr.c_str());
    XMLDateTime exp(expstr.get());
    exp.parseDateTime();
    if (exp.getEpoch() < time(nullptr) - XMLToolingConfig::getConfig().clock_skew_secs) {
        throw IOException("Decrypted data has expired.");
    }

    return decrypted.substr(i + 20);
}
