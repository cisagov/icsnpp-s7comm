# @TEST-EXEC: zeek -C -r ${TRACES}/s7comm_plus_port_change.pcap "S7COMM::ports += { 5678/tcp }" %INPUT
# @TEST-EXEC: btest-diff cotp.log
# @TEST-EXEC: btest-diff s7comm.log
# @TEST-EXEC: btest-diff s7comm_plus.log
#
# @TEST-DOC: Test S7comm Plus traffic on a non-standard TCP port while retaining the default TCP port.

@load icsnpp/s7comm

event zeek_init() &priority=4
    {
    if ( 102/tcp !in S7COMM::ports )
        Reporter::fatal("The default S7comm port was removed by additive configuration");

    if ( 5678/tcp !in S7COMM::ports )
        Reporter::fatal("The custom S7comm port was not added");

    if ( 5678/tcp !in likely_server_ports )
        Reporter::fatal("The custom S7comm port was not added to likely_server_ports");
    }
