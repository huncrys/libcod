CXXFLAGS = -DNDEBUG -g -O2 -fpermissive
#CXXFLAGS = -g
# -fPIC is supported. Please report any breakage of -fPIC as a bug.
CXXFLAGS += -fPIC
# the following options reduce code size, but breaks link or makes link very slow on some systems
# CXXFLAGS += -ffunction-sections -fdata-sections
# LDFLAGS += -Wl,--gc-sections
ARFLAGS = -cr	# ar needs the dash on OpenBSD
RANLIB = ranlib
CP = cp
MKDIR = mkdir
EGREP = egrep
UNAME = $(shell uname)
ISX86 = $(shell uname -m | $(EGREP) -c "i.86|x86|i86|amd64")

ifeq ($(CXX),gcc)	# for some reason CXX is gcc on cygwin 1.1.4
CXX = g++
endif

ifeq ($(ISX86),1)

GCC42_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[2-9]|[5-9])")
INTEL_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\)")
ICC111_OR_LATER = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\) ([2-9][0-9]|1[2-9]|11\.[1-9])")
IS_SUN_CC = $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: Sun")
GAS210_OR_LATER = $(shell echo "" | $(AS) -v 2>&1 | $(EGREP) -c "GNU assembler version (2\.[1-9][0-9]|[3-9])")
GAS217_OR_LATER = $(shell echo "" | $(AS) -v 2>&1 | $(EGREP) -c "GNU assembler version (2\.1[7-9]|2\.[2-9]|[3-9])")
GAS219_OR_LATER = $(shell echo "" | $(AS) -v 2>&1 | $(EGREP) -c "GNU assembler version (2\.19|2\.[2-9]|[3-9])")
ISMINGW = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "mingw")

ifneq ($(INTEL_COMPILER),0)
CXXFLAGS += -wd68 -wd186 -wd279 -wd327
ifeq ($(ICC111_OR_LATER),0)
# "internal error: backend signals" occurs on some x86 inline assembly with ICC 9 and some x64 inline assembly with ICC 11.0
# if you want to use Crypto++'s assembly code with ICC, try enabling it on individual files
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
endif
endif

ifeq ($(GAS210_OR_LATER),0)	# .intel_syntax wasn't supported until GNU assembler 2.10
CXXFLAGS += -DCRYPTOPP_DISABLE_ASM
else
ifeq ($(GAS217_OR_LATER),0)
CXXFLAGS += -DCRYPTOPP_DISABLE_SSSE3
else
ifeq ($(GAS219_OR_LATER),0)
CXXFLAGS += -DCRYPTOPP_DISABLE_AESNI
endif
endif
ifeq ($(UNAME),SunOS)
CXXFLAGS += -Wa,--divide	# allow use of "/" operator
endif
endif

ifeq ($(ISMINGW),1)
LDLIBS += -lws2_32
endif

endif	# ISX86

ifeq ($(UNAME),Darwin)
AR = libtool
ARFLAGS = -static -o
CXX = c++
IS_GCC2 = $(shell $(CXX) -v 2>&1 | $(EGREP) -c gcc-932)
ifeq ($(IS_GCC2),1)
CXXFLAGS += -fno-coalesce-templates -fno-coalesce-static-vtables
LDLIBS += -lstdc++
LDFLAGS += -flat_namespace -undefined suppress -m
endif
endif

ifneq ($(IS_SUN_CC),0)	# override flags for CC Sun C++ compiler
CXXFLAGS = -DNDEBUG -O -g0 -native -template=no%extdef $(M32OR64)
LDFLAGS =
AR = $(CXX)
ARFLAGS = -xar -o
RANLIB = true
SUN_CC10_BUGGY = $(shell $(CXX) -V 2>&1 | $(EGREP) -c "CC: Sun .* 5\.10 .* (2009|2010/0[1-4])")
ifneq ($(SUN_CC10_BUGGY),0)
# -DCRYPTOPP_INCLUDE_VECTOR_CC is needed for Sun Studio 12u1 Sun C++ 5.10 SunOS_i386 128229-02 2009/09/21 and was fixed in May 2010
# remove it if you get "already had a body defined" errors in vector.cc
CXXFLAGS += -DCRYPTOPP_INCLUDE_VECTOR_CC
endif
endif

SRCS = $(wildcard *.cpp)
ifeq ($(SRCS),)				# workaround wildcard function bug in GNU Make 3.77
SRCS = $(shell echo *.cpp)
endif

OBJS = $(SRCS:.cpp=.o)
# test.o needs to be after bench.o for cygwin 1.1.4 (possible ld bug?)
TESTOBJS = bench.o bench2.o test.o validat1.o validat2.o validat3.o adhoc.o datatest.o regtest.o fipsalgt.o dlltest.o
LIBOBJS = $(filter-out $(TESTOBJS),$(OBJS))
LIB32OBJS = $(patsubst %.o, %.32.o, $(LIBOBJS))
LIB64OBJS = $(patsubst %.o, %.64.o, $(LIBOBJS))

all: libcrypto

clean:
	$(RM) libcrypto32.a libcrypto64.a $(LIB32OBJS) $(LIB64OBJS)

libcrypto32.a: $(LIB32OBJS)
	$(AR) $(ARFLAGS) $@ $(LIB32OBJS)
	$(RANLIB) $@

libcrypto64.a: $(LIB64OBJS)
	$(AR) $(ARFLAGS) $@ $(LIB64OBJS)
	$(RANLIB) $@

libcrypto: libcrypto32.a libcrypto64.a

adhoc.cpp: adhoc.cpp.proto
ifeq ($(wildcard adhoc.cpp),)
	cp adhoc.cpp.proto adhoc.cpp
else
	touch adhoc.cpp
endif

%.32.o : %.cpp
	$(CXX) $(CXXFLAGS) -m32 -c $< -o $@

%.64.o : %.cpp
	$(CXX) $(CXXFLAGS) -m64 -c $< -o $@