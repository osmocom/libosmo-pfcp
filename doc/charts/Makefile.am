msc: \
	$(builddir)/pfcp_msgs.png \
	$(builddir)/pfcp_msgs_gtp.png \
	$(NULL)

dot: \
	$(builddir)/pfcp_overview.png \
	$(builddir)/pfcp_cp_peer_fsm.png \
	$(builddir)/pfcp_up_peer_fsm.png \
	$(builddir)/pfcp_heartbeat_fsm.png \
	$(builddir)/pfcp_cp_session_fsm.png \
	$(builddir)/pfcp_up_session_fsm.png \
	$(builddir)/pfcp_and_gtp.png \
	$(NULL)

$(builddir)/%.png: $(srcdir)/%.msc
	mscgen -T png -o $@ $<

$(builddir)/%.png: $(srcdir)/%.dot
	dot -Tpng $< > $@

$(srcdir)/%.msc: $(srcdir)/%.ladder
	@which ladder_to_msc.py || (echo 'PLEASE POINT YOUR $$PATH AT libosmocore/contrib/ladder_to_msc.py' && false)
	ladder_to_msc.py -i $< -o $@

.PHONY: poll
poll:
	while true; do $(MAKE) msc dot; sleep 1; done
