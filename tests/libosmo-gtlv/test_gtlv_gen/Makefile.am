AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(bulddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

noinst_PROGRAMS = \
	gen__myproto_ies_auto \
	gtlv_gen_test \
	$(NULL)

EXTRA_DIST = \
	myproto_ies_custom.h \
	gtlv_gen_test.ok \
	$(NULL)

BUILT_SOURCES = \
	myproto_ies_auto.h \
	myproto_ies_auto.c \
	$(NULL)

CLEANFILES = \
	myproto_ies_auto.h \
	myproto_ies_auto.c \
	$(NULL)

gen__myproto_ies_auto_SOURCES = \
	gen__myproto_ies_auto.c \
	myproto_ies_custom.c \
	$(NULL)

gen__myproto_ies_auto_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

myproto_ies_auto.h: $(builddir)/gen__myproto_ies_auto
	$(builddir)/gen__myproto_ies_auto h > $(builddir)/myproto_ies_auto.h
myproto_ies_auto.c: $(builddir)/gen__myproto_ies_auto
	$(builddir)/gen__myproto_ies_auto c > $(builddir)/myproto_ies_auto.c

gtlv_gen_test_SOURCES = \
	gtlv_gen_test.c \
	myproto_ies_custom.c \
	myproto_ies_auto.c \
	$(NULL)

gtlv_gen_test_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.a \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/gtlv_gen_test >$(srcdir)/gtlv_gen_test.ok
