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
 * @file exceptions.h
 * 
 * Exception classes
 */
 
#if !defined(__xmltooling_exceptions_h__)
#define __xmltooling_exceptions_h__

#include <map>
#include <string>
#include <vector>
#include <iostream>
#include <xmltooling/base.h>

/**
 * Declares a derived exception class
 * 
 * @param name  the exception class
 * @param base  the base class
 */
#define DECL_XMLTOOLING_EXCEPTION(name,base) \
    class XMLTOOL_EXCEPTIONAPI(XMLTOOL_API) name : public xmltooling::base { \
    public: \
        name(const char* msg=NULL, const xmltooling::params& p=xmltooling::params()) \
            : xmltooling::base(msg,p) {} \
        name(const char* msg, const xmltooling::namedparams& p) \
            : xmltooling::base(msg,p) {} \
        name(const std::string& msg, const xmltooling::params& p=xmltooling::params()) \
            : xmltooling::base(msg,p) {} \
        name(const std::string& msg, const xmltooling::namedparams& p) \
            : xmltooling::base(msg,p) {} \
        virtual ~name() {} \
        virtual const char* getClassName() const { return "xmltooling::"#name; } \
        void raise() const {throw *this;} \
    }

/**
 * Declares a factory function for an exception class.
 * 
 * @param name  the exception class name
 */
#define DECL_EXCEPTION_FACTORY(name) \
    xmltooling::XMLToolingException* name##Factory() \
    { \
        return new xmltooling::name(); \
    }

/**
 * Registers a factory for an exception class.
 * 
 * @param name  the exception class name
 */
#define REGISTER_EXCEPTION_FACTORY(name) XMLToolingException::registerFactory("xmltooling::"#name,name##Factory)

namespace xmltooling {
    
    /**
     * Wrapper around a variable number of arguments.
     */
    class XMLTOOL_API params
    {
    public:
        /**
         * Initializes with zero parameters.
         */
        params() {}
        
        /**
         * Initializes the parameter set.
         * 
         * @param count     the number of parameters that follow
         */
        params(int count,...);
        
        /**
         * Returns an immutable reference to the set of parameters.
         * 
         * @return the parameter set
         */
        const std::vector<const char*>& get() const {return v;}
        
    protected:
        std::vector<const char*> v;
    };
    
    /**
     * Wrapper around a variable number of name/value pairs.
     */
    class XMLTOOL_API namedparams : public params
    {
    public:
        /**
         * Initializes with zero parameters.
         */
        namedparams() {}

        /**
         * Initializes the named parameter set.
         * 
         * @param count     the number of name/value pairs that follow (must be even)
         */
        namedparams(int count,...);
    };

    /**
     * Base exception class, supports parametrized messages and XML serialization.
     * Parameters are prefixed with a dollar sign ($) and can be positional ($1)
     * or named ($info).
     */
    class XMLTOOL_EXCEPTIONAPI(XMLTOOL_API) XMLToolingException;
    typedef XMLToolingException* ExceptionFactory();
    
    class XMLTOOL_EXCEPTIONAPI(XMLTOOL_API) XMLToolingException
    {
    public:
        virtual ~XMLToolingException() {}

        /**
         * Constructs an exception using a message and positional parameters.
         * 
         * @param msg   error message
         * @param p     an ordered set of positional parameter strings
         */
        XMLToolingException(const char* msg=NULL, const params& p=params());

        /**
         * Constructs an exception using a message and named parameters.
         * 
         * @param msg   error message
         * @param p     a set of named parameter strings
         */
        XMLToolingException(const char* msg, const namedparams& p);

        /**
         * Constructs an exception using a message and positional parameters.
         * 
         * @param msg   error message
         * @param p     an ordered set of positional parameter strings
         */
        XMLToolingException(const std::string& msg, const params& p=params());

        /**
         * Constructs an exception using a message and named parameters.
         * 
         * @param msg   error message
         * @param p     a set of named parameter strings
         */
        XMLToolingException(const std::string& msg, const namedparams& p);

        /**
         * Returns the error message, after processing any parameter references.
         * 
         * @return  the processed message
         */
        const char* getMessage() const;

        /**
         * Returns the error message, after processing any parameter references.
         * 
         * @return  the processed message
         */
        const char* what() const {return getMessage();}

        /**
         * Sets the error message.
         * 
         * @param msg   the error message
         */
        void setMessage(const char* msg);

        /**
         * Sets the error message.
         * 
         * @param msg   the error message
         */
        void setMessage(const std::string& msg) {
            setMessage(msg.c_str());
        }

        /**
         * Attach a set of positional parameters to the exception.
         * 
         * @param p     an ordered set of named parameter strings
         */
        void addProperties(const params& p);
        
        /**
         * Attach a set of named parameters to the exception.
         * 
         * @param p     a set of named parameter strings
         */
        void addProperties(const namedparams& p);

        /**
         * Attach a single positional parameter at the next available position.
         * 
         * @param value the parameter value
         */
        void addProperty(const char* value) {
            addProperties(params(1,value));
        }

        /**
         * Attach a single named parameter.
         * 
         * @param name  the parameter name
         * @param value the parameter value
         */
        void addProperty(const char* name, const char* value) {
            addProperties(namedparams(1,name,value));
        }

        /**
         * Returns the parameter property with the designated position (based from one).
         * 
         * @param index     position to access
         * @return  the parameter property or NULL
         */
        const char* getProperty(unsigned int index) const;

        /**
         * Returns the parameter property with the designated name.
         * 
         * @param name     named parameter to access
         * @return  the parameter property or NULL
         */
        const char* getProperty(const char* name) const;

        /**
         * Raises an exception using itself.
         * Used to raise an exception of a derived type.
         */
        virtual void raise() const {
            throw *this;
        }

        /**
         * Returns a unique name for the exception class.
         * 
         * @return class name
         */
        virtual const char* getClassName() const {
            return "xmltooling::XMLToolingException";
        }
        
        /**
         * Returns a string containing a serialized representation of the exception.
         * 
         * @return  the serialization
         */
        std::string toString() const;

    private:
        std::string m_msg;
        mutable std::string m_processedmsg;
        std::map<std::string,std::string> m_params;

    public:
        /**
         * Builds an empty exception of the given type.
         * 
         * @param exceptionClass    the name of the exception type to build
         * @return an empty exception object
         */
        static XMLToolingException* getInstance(const char* exceptionClass);

        /**
         * Builds an exception from a serialized input stream.
         * 
         * @param in    input stream
         * @return the exception object found in the stream
         */
        static XMLToolingException* fromStream(std::istream& in);
        
        /**
         * Builds an exception from a serialized input buffer.
         * 
         * @param s   input buffer
         * @return the exception object found in the buffer
         */
        static XMLToolingException* fromString(const char* s);
                
        /**
         * Registers a factory to create exceptions of a given class name.
         * 
         * @param exceptionClass    name of exception type
         * @param factory           factory function to build exceptions with
         */
        static void registerFactory(const char* exceptionClass, ExceptionFactory* factory) {
            m_factoryMap[exceptionClass] = factory;
        }
        
        /**
         * Unregisters the factory for a given class name.
         * 
         * @param exceptionClass    name of exception type
         */
        static void deregisterFactory(const char* exceptionClass) {
            m_factoryMap.erase(exceptionClass);
        }

    private:
        typedef std::map<std::string,ExceptionFactory*> ExceptionFactoryMap;
        static ExceptionFactoryMap m_factoryMap;
    };

    DECL_XMLTOOLING_EXCEPTION(XMLParserException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(XMLObjectException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(MarshallingException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(UnmarshallingException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(UnknownElementException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(UnknownAttributeException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(ValidationException,XMLToolingException);
    DECL_XMLTOOLING_EXCEPTION(SignatureException,XMLToolingException);

};

#endif /* __xmltooling_exceptions_h__ */
