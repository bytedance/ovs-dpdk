bin_PROGRAMS += tools/pkt-sender

tools_pkt_sender_SOURCES = \
	tools/pkt-sender.c

tools_pkt_sender_LDADD = \
	lib/libopenvswitch.la

tools_pkt_sender_LDFLAGS = $(AM_LDFLAGS)
