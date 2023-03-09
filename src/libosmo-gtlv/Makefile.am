AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	-I$(builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

lib_LTLIBRARIES = \
	libosmo-gtlv.la \
	$(NULL)

libosmo_gtlv_la_SOURCES = \
	gtlv.c \
	gtlv_dec_enc.c \
	gtlv_gen.c \
	$(NULL)

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=1:0:0

libosmo_gtlv_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined -export-symbols-regex '^osmo_'
