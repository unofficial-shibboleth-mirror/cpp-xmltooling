AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -DDATADIR=\"$(srcdir)/data/\"

TESTS = xmltoolingtest

check_PROGRAMS = xmltoolingtest

xmltoolingtest_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	$(CXXTESTFLAGS) \
	$(xerces_CFLAGS) \
	$(log4shib_CFLAGS) \
	$(log4cpp_CFLAGS) \
	$(BOOST_CPPFLAGS)

if BUILD_XMLSEC
xmltoolingtest_CXXFLAGS += $(XMLSEC_CFLAGS)
xmltoolingtest_LDADD = $(top_builddir)/xmltooling/libxmltooling.la $(XMLSEC_LIBS)
else
xmltoolingtest_LDADD = $(top_builddir)/xmltooling/libxmltooling-lite.la
endif
xmltoolingtest_LDADD += $(xerces_LIBS) $(log4shib_LIBS) $(log4cpp_LIBS)

if BUILD_XMLSEC
xmlsec_sources = \
	BadKeyInfoTest.cpp \
	DataSealerTest.cpp \
	EncryptionTest.cpp \
	FilesystemCredentialResolverTest.cpp \
	ExplicitKeyTrustEngineTest.cpp \
	InlineKeyResolverTest.cpp \
	KeyInfoTest.cpp \
	MemoryStorageServiceTest.cpp \
	NonVisibleNamespaceTest.cpp \
	PKIXEngineTest.cpp \
	SecurityHelperTest.cpp \
	SignatureTest.cpp
endif

xmltoolingtest_sources = \
	CloneInputStreamTest.cpp \
	ComplexXMLObjectTest.cpp \
	DateTimeTest.cpp \
	DirectoryWalkerTest.cpp \
	ExceptionTest.cpp \
	MarshallingTest.cpp \
	SOAPTest.cpp \
	UnmarshallingTest.cpp \
	TemplateEngineTest.cpp \
	${xmlsec_sources}

noinst_HEADERS = \
	XMLObjectBaseTestCase.h \
	xmltoolingtest.h \
	$(xmltoolingtest_sources:.cpp=.h)

nodist_xmltoolingtest_SOURCES = xmltoolingtest.cpp $(xmltoolingtest_sources)

xmltoolingtest.cpp: %.cpp: %.h
	$(CXXTEST) --error-printer --have-eh --have-std --abort-on-fail -o $@ $<

$(xmltoolingtest_sources): %.cpp: %.h
	$(CXXTEST) --part --have-eh --have-std --abort-on-fail -o $@ $<

CLEANFILES = $(nodist_xmltoolingtest_SOURCES)

EXTRA_DIST = data
