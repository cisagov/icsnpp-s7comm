# @TEST-EXEC: zeek -C -r ${TRACES}/snap7.pcap %INPUT
#
# @TEST-DOC: Test S7comm Plus traffic from packet captures found freely available online.

@load icsnpp/s7comm
