SUBDIRS = \
	test_gtlv_gen \
	test_tliv \
	$(NULL)

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
	gtlv_dec_enc_test \
	$(NULL)

EXTRA_DIST = \
	gtlv_test.ok \
	gtlv_dec_enc_test.ok \
	$(NULL)

gtlv_test_SOURCES = \
	gtlv_test.c \
	$(NULL)

gtlv_test_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

gtlv_dec_enc_test_SOURCES = \
	gtlv_dec_enc_test.c \
	$(NULL)

gtlv_dec_enc_test_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gtlv_test >$(srcdir)/gtlv_test.ok
	$(builddir)/gtlv_dec_enc_test >$(srcdir)/gtlv_dec_enc_test.ok
	$(MAKE) -C test_gtlv_gen update_exp
	$(MAKE) -C test_tliv update_exp
