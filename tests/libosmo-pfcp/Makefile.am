AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(NULL)

check_PROGRAMS = \
	pfcp_test \
	$(NULL)

EXTRA_DIST = \
	pfcp_test.ok \
	$(NULL)

pfcp_test_SOURCES = \
	pfcp_test.c \
	$(NULL)

pfcp_test_LDADD = \
	$(top_builddir)/src/libosmo-pfcp/libosmo-pfcp.la \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.la \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/pfcp_test >$(srcdir)/pfcp_test.ok
