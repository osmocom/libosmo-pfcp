AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir) \
	-I$(builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

noinst_LIBRARIES = \
	libosmo-pfcp.a \
	$(NULL)

libosmo_pfcp_a_SOURCES = \
	pfcp_strs.c \
	$(NULL)
