if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= example-cfg.json

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

minerd_SOURCES	= elist.h miner.h compat.h cpu-miner.cpp util.c hash/haval.cpp hash/keccak.cpp \
	hash/ripemd.cpp hash/sha2big.cpp hash/sha2.cpp hash/tiger.cpp hash/whirlpool.cpp
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ -lgmp
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@
