# @TEST-EXEC: zeek -C -r ${TRACES}/s7comm_plus.pcap %INPUT
#
# @TEST-DOC: Test S7comm Plus traffic captured in Idaho National Laboratory's (INL) Control Environment Laboratory Resource (CELR).

@load icsnpp/s7comm
