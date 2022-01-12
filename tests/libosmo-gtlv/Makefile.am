AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

noinst_PROGRAMS = \
	gtlv_test \
	$(NULL)

EXTRA_DIST = \
	gtlv_test.ok \
	$(NULL)

gtlv_test_SOURCES = \
	gtlv_test.c \
	$(NULL)

gtlv_test_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gtlv_test >$(srcdir)/gtlv_test.ok
