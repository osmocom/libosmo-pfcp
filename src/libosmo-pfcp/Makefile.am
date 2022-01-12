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
	pfcp_ies_custom.c \
	pfcp_msg.c \
	pfcp_strs.c \
	\
	pfcp_ies_auto.c \
	$(NULL)

BUILT_SOURCES = \
	pfcp_ies_auto.c \
	$(NULL)

CLEANFILES = \
	pfcp_ies_auto.c \
	$(NULL)

pfcp_ies_auto.c: $(srcdir)/gen__pfcp_ies_auto.c \
		 $(top_srcdir)/src/libosmo-gtlv/gtlv_gen.c \
		 $(top_srcdir)/include/osmocom/gtlv/gtlv_gen.h
	$(MAKE) -C $(top_builddir)/src/libosmo-gtlv
	$(MAKE) gen__pfcp_ies_auto
	$(builddir)/gen__pfcp_ies_auto c > $(builddir)/pfcp_ies_auto.c

noinst_PROGRAMS = \
	gen__pfcp_ies_auto \
	$(NULL)

gen__pfcp_ies_auto_SOURCES = \
	gen__pfcp_ies_auto.c \
	$(NULL)

gen__pfcp_ies_auto_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.a \
	$(LIBOSMOCORE_LIBS) \
	$(COVERAGE_LDFLAGS) \
	$(NULL)
