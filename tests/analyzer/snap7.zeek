# @TEST-EXEC: zeek -C -r ${TRACES}/snap7.pcap %INPUT
# @TEST-EXEC: btest-diff cotp.log
# @TEST-EXEC: btest-diff s7comm.log
# @TEST-EXEC: btest-diff s7comm_read_szl.log
# @TEST-EXEC: btest-diff s7comm_upload_download.log
#
# @TEST-DOC: Test S7comm Plus traffic from packet captures found freely available online.

@load icsnpp/s7comm
