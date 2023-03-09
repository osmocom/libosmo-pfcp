AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(bulddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(NULL)

check_PROGRAMS = \
	gen__myproto_ies_auto \
	tliv_test \
	$(NULL)

EXTRA_DIST = \
	myproto_ies_custom.h \
	tliv_test.ok \
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
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

myproto_ies_auto.h: $(builddir)/gen__myproto_ies_auto
	$(builddir)/gen__myproto_ies_auto h > $(builddir)/myproto_ies_auto.h
myproto_ies_auto.c: $(builddir)/gen__myproto_ies_auto
	$(builddir)/gen__myproto_ies_auto c > $(builddir)/myproto_ies_auto.c

tliv_test_SOURCES = \
	tliv_test.c \
	myproto_ies_custom.c \
	myproto_ies_auto.c \
	$(NULL)

tliv_test_LDADD = \
	$(top_builddir)/src/libosmo-gtlv/libosmo-gtlv.la \
	$(LIBOSMOCORE_LIBS) \
	$(NULL)

.PHONY: update_exp
update_exp:
	$(builddir)/tliv_test >$(srcdir)/tliv_test.ok
