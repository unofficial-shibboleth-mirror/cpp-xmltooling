/*
 *  Copyright 2001-2007 Internet2
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
 * @file xmltooling/util/PathResolver.h
 * 
 * Resolves local filenames into absolute pathnames.
 */

#if !defined(__xmltooling_pathres_h__)
#define __xmltooling_pathres_h__

#include <xmltooling/base.h>

#include <string>

namespace xmltooling {

    /**
     * Resolves local filenames into absolute pathnames.
     */
    class XMLTOOL_API PathResolver
    {
        MAKE_NONCOPYABLE(PathResolver);
    public:
        PathResolver() : m_defaultPackage("xmltooling"), m_defaultPrefix("/usr") {}

        virtual ~PathResolver() {}
        
        /** Types of file resources to resolve. */
        enum file_type_t {
            XMLTOOLING_LIB_FILE,
            XMLTOOLING_LOG_FILE,
            XMLTOOLING_XML_FILE,
            XMLTOOLING_RUN_FILE,
            XMLTOOLING_CFG_FILE
        };
        
        /**
         * Set the default package to use when resolving files.
         *
         * @param pkgname name of default package to use 
         */
        virtual void setDefaultPackageName(const char* pkgname) {
            m_defaultPackage = pkgname;
        }

        /**
         * Set the default istallation prefix to use when resolving files.
         *
         * @param prefix name of default prefix to use 
         */
        virtual void setDefaultPrefix(const char* prefix) {
            m_defaultPrefix = prefix;
        }
        
        /**
         * Changes the input filename into an absolute pathname to the same file.
         * 
         * @param s         filename to resolve
         * @param filetype  type of file being resolved
         * @param pkgname   application package name to use in resolving the file (or NULL for the default)
         * @param prefix    installation prefix to use in resolving the file (or NULL for the default)
         * 
         * @return a const reference to the input string
         */
        virtual const std::string& resolve(std::string& s, file_type_t filetype, const char* pkgname=NULL, const char* prefix=NULL) const;

    private:
        bool isAbsolute(const char* s) const {
            switch (*s) {
                case '/':
                case '\\':
                    return true;
                case '.':
                    return (*(s+1) == '.' || *(s+1) == '/' || *(s+1) == '\\');
            }
            return *(s+1) == ':';
        }

        std::string m_defaultPackage,m_defaultPrefix;
    };
};

#endif /* __xmltooling_pathres_h__ */
