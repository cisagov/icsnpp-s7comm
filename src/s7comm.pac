%include zeek/binpac.pac
%include zeek/zeek.pac

%extern{
    #include "events.bif.h"
%}

analyzer S7COMM withcontext {
    connection: S7COMM_Conn;
    flow:       S7COMM_Flow;
};

connection S7COMM_Conn(zeek_analyzer: ZeekAnalyzer) {
    upflow   = S7COMM_Flow(true);
    downflow = S7COMM_Flow(false);
};

%include s7comm-protocol.pac

flow S7COMM_Flow(is_orig: bool) {
    datagram = S7COMM_PDU(is_orig) withcontext(connection, this);
}

%include s7comm-analyzer.pac