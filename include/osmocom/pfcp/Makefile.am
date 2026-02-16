noinst_HEADERS = \
	pfcp_endpoint_private.h \
	pfcp_cp_peer_private.h \
	$(NULL)

version.h: version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

EXTRA_DIST = \
	version.h.tpl \
	$(NULL)

pfcp_HEADERS = \
	pfcp_endpoint.h \
	pfcp_ies_custom.h \
	pfcp_ies_auto.h \
	pfcp_msg.h \
	pfcp_proto.h \
	pfcp_strs.h \
	pfcp_cp_peer.h \
	version.h \
	$(NULL)

pfcpdir = $(includedir)/osmocom/pfcp

BUILT_SOURCES = \
	pfcp_ies_auto.h \
	$(NULL)

CLEANFILES = \
	pfcp_ies_auto.h \
	$(NULL)

pfcp_ies_auto.h: $(top_srcdir)/src/libosmo-pfcp/gen__pfcp_ies_auto.c \
		 $(top_srcdir)/src/libosmo-gtlv/gtlv_gen.c \
		 $(top_srcdir)/include/osmocom/gtlv/gtlv_gen.h
	$(MAKE) -C $(top_builddir)/src/libosmo-gtlv
	$(MAKE) -C $(top_builddir)/src/libosmo-pfcp gen__pfcp_ies_auto
	$(top_builddir)/src/libosmo-pfcp/gen__pfcp_ies_auto h > $(builddir)/pfcp_ies_auto.h
