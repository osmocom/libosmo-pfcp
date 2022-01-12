pfcp_HEADERS = \
	pfcp_endpoint.h \
	pfcp_heartbeat_fsm.h \
	pfcp_ies_custom.h \
	pfcp_ies_auto.h \
	pfcp_msg.h \
	pfcp_proto.h \
	pfcp_strs.h \
	pfcp_cp_peer.h \
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
