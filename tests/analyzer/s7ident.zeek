# @TEST-EXEC: zeek -C -r ${TRACES}/s7ident.pcap %INPUT
# @TEST-EXEC: btest-diff cotp.log
# @TEST-EXEC: btest-diff s7comm.log
# @TEST-EXEC: btest-diff s7comm_known_devices.log
#
# @TEST-DOC: Test S7comm Plus identification string

@load icsnpp/s7comm
