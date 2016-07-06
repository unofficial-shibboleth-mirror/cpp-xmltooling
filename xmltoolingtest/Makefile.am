AUTOMAKE_OPTIONS = foreign

TESTS = xmltoolingtest

check_PROGRAMS = xmltoolingtest

xmltoolingtest_CXXFLAGS = $(CXXTESTFLAGS) $(xerces_CFLAGS)
if BUILD_XMLSEC
xmltoolingtest_CXXFLAGS += $(XMLSEC_CFLAGS)
xmltoolingtest_LDADD = $(top_builddir)/xmltooling/libxmltooling.la $(XMLSEC_LIBS)
else
xmltoolingtest_LDADD = $(top_builddir)/xmltooling/libxmltooling-lite.la
endif
xmltoolingtest_LDADD += $(xerces_LIBS)

if BUILD_XMLSEC
xmlsec_sources = \
	DataSealerTest.cpp \
	EncryptionTest.cpp \
	FilesystemCredentialResolverTest.cpp \
	ExplicitKeyTrustEngineTest.cpp \
	InlineKeyResolverTest.cpp \
	MemoryStorageServiceTest.cpp \
	PKIXEngineTest.cpp \
	SecurityHelperTest.cpp \
	SignatureTest.cpp
endif

xmltoolingtest_sources = \
	ComplexXMLObjectTest.cpp \
	DateTimeTest.cpp \
	DirectoryWalkerTest.cpp \
	ExceptionTest.cpp \
	KeyInfoTest.cpp \
	MarshallingTest.cpp \
	NonVisibleNamespaceTest.cpp \
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
