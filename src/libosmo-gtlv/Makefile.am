AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	-I$(builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libosmo-gtlv.a \
	$(NULL)

libosmo_gtlv_a_SOURCES = \
	gtlv.c \
	$(NULL)
