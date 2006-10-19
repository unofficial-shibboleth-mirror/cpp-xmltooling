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
 * @file xmltooling/util/TemplateEngine.h
 * 
 * Simple template replacement engine.
 */

#ifndef __xmltooling_template_h__
#define __xmltooling_template_h__

#include <xmltooling/base.h>

#include <map>
#include <string>
#include <iostream>

namespace xmltooling {

    /**
     * Simple template replacement engine. Supports the following:
     * <ul>
     *  <li> &lt;mlp key/&gt; </li>
     *  <li> &lt;mlpif key&gt; stuff &lt;/mlpif&gt;</li>
     *  <li> &lt;mlpifnot key&gt; stuff &lt;/mlpifnot&gt;</li>
     * </ul>
     * 
     * The default tag prefix is "mlp". This can be overridden for
     * compatibility.
     */
    class XMLTOOL_API TemplateEngine
    {
        MAKE_NONCOPYABLE(TemplateEngine);
    public:
        
        TemplateEngine() {
            setTagPrefix("mlp"); 
        }

        virtual ~TemplateEngine() {}
        
        /**
         * Sets the tag name to use when locating template replacement tags.
         * 
         * @param tagPrefix base prefix for tags
         */
        void setTagPrefix(const char* tagPrefix);
        
        /**
         * Processes template from an input stream and executes replacements and
         * conditional logic based on parameters. 
         * 
         * @param is            input stream providing template
         * @param os            output stream to send results of executing template
         * @param parameters    name/value parameters to plug into template
         * @param e             optional exception to extract parameters from
         */
        virtual void run(
            std::istream& is,
            std::ostream& os,
            const std::map<std::string,std::string>& parameters,
            const XMLToolingException* e=NULL
            ) const;

    private:
        void trimspace(std::string& s) const;
        void html_encode(std::ostream& os, const char* start) const;
        void process(
            bool visible,
            const std::string& buf,
            const char*& lastpos,
            std::ostream& os,
            const std::map<std::string,std::string>& parameters,
            const XMLToolingException* e
            ) const;
            
        std::string keytag,iftag,ifendtag,ifnottag,ifnotendtag;
    };
};

#endif /* __xmltooling_template_h__ */
