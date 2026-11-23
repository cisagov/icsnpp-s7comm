# @TEST-EXEC: zeek -C -r ${TRACES}/s7comm_szl_fragmented.pcap %INPUT
# @TEST-EXEC: btest-diff s7comm.log
# @TEST-EXEC: btest-diff s7comm_read_szl.log
# @TEST-EXEC: btest-diff s7comm_known_devices.log
# @TEST-EXEC: test ! -f analyzer.log
#
# @TEST-DOC: Test a module identification list (SZL 0x0011) sent in two parts, followed by another Read SZL

@load icsnpp/s7comm
