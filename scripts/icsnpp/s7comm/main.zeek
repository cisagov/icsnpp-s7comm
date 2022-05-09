##! main.zeek
##!
##! Binpac s7comm Analyzer - Contains the base script-layer functionality for
##!                          processing events emitted from the analyzer.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module S7COMM;

export{
    redef enum Log::ID += { LOG_COTP, 
                            LOG_S7COMM, 
                            LOG_S7COMM_PLUS };

    ###############################################################################################
    #####################################  COTP -> cotp.log  ######################################
    ###############################################################################################
    type COTP: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        pdu_code                : string    &log;   # COTP PDU Type Code (in hex)
        pdu_name                : string    &log;   # COTP PDU Type Name
    };
    global log_cotp: event(rec: COTP);

    ###############################################################################################
    ###################################  S7COMM -> s7comm.log  ####################################
    ###############################################################################################
    type S7COMM: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        rosctr_code             : count     &log;   # Remote Operating Service Control Code (in hex)
        rosctr_name             : string    &log;   # Remote Operating Service Control Name
        pdu_reference           : count     &log;   # Reference ID Used to Link Requests to Responses
        function_code           : string    &log;   # Parameter Function Code (in hex)
        function_name           : string    &log;   # Parameter Function Name
        error_class             : string    &log;   # Error Class Name
        error_code              : string    &log;   # Error Code within Error Class
    };
    global log_s7comm: event(rec: S7COMM);

    ###############################################################################################
    ###############################  S7COMM_PLUS -> s7comm_plus.log  ##############################
    ###############################################################################################
    type S7COMM_PLUS: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        version                 : count     &log;   # S7comm-plus Version
        opcode                  : string    &log;   # Opcode Code (in hex)
        opcode_name             : string    &log;   # Opcode Name
        function_code           : string    &log;   # Opcode Function Code (in hex)
        function_name           : string    &log;   # Opcode Function Name
    };
    global log_s7comm_plus: event(rec: S7COMM_PLUS);
}

# All these protocols operate on TCP port 102
const ports = {
    102/tcp,
};
redef likely_server_ports += { ports };

###################################################################################################
###############  Defines Log Streams for cotp.log, s7comm.log, and s7comm_plus.log  ###############
###################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(S7COMM::LOG_COTP, [$columns=COTP,
                                          $ev=log_cotp,
                                          $path="cotp"]);

    Log::create_stream(S7COMM::LOG_S7COMM, [$columns=S7COMM,
                                            $ev=log_s7comm,
                                            $path="s7comm"]);

    Log::create_stream(S7COMM::LOG_S7COMM_PLUS, [$columns=S7COMM_PLUS,
                                            $ev=log_s7comm_plus,
                                            $path="s7comm_plus"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_S7COMM_TCP, ports);
}

###################################################################################################
###########################  Defines logging of cotp event -> cotp.log  ###########################
###################################################################################################
event cotp(c: connection,
           pdu: count) {

    add c$service["cotp"];
    local cotp_item: COTP;
    cotp_item$ts  = network_time();
    cotp_item$uid = c$uid;
    cotp_item$id  = c$id;

    cotp_item$pdu_code = fmt("0x%02x", pdu);
    cotp_item$pdu_name = cotp_pdu_types[pdu];

    Log::write(LOG_COTP, cotp_item);
}

###################################################################################################
#####################  Defines logging of s7comm_header event -> s7comm.log  ######################
###################################################################################################
event s7comm_header(c: connection,
                    rosctr: count,
                    pdu_reference: count,
                    function_code: count,
                    error_class: count,
                    error_code: count) {

    add c$service["s7comm"];
    local s7comm_item: S7COMM;

    s7comm_item$ts  = network_time();
    s7comm_item$uid = c$uid;
    s7comm_item$id  = c$id;

    s7comm_item$rosctr_code = rosctr;
    s7comm_item$rosctr_name = rosctr_types[rosctr];
    s7comm_item$pdu_reference = pdu_reference;

    if ( function_code != 0xff )
    {
        s7comm_item$function_code = fmt("0x%02x", function_code);
        s7comm_item$function_name = s7comm_functions[function_code];
    }

    if ( rosctr == 0x03 || rosctr == 0x02 )
    {
        s7comm_item$error_class = s7comm_error_class[error_class];
        s7comm_item$error_code = fmt("0x%02x", error_code);
    }

    Log::write(LOG_S7COMM, s7comm_item);
}

###################################################################################################
#################  Defines logging of s7comm_plus_header event -> s7comm_plus.log  ################
###################################################################################################
event s7comm_plus_header(c: connection,
                         version: count,
                         opcode: count,
                         function_code: count) {

    add c$service["s7comm-plus"];
    local s7comm_plus_item: S7COMM_PLUS;

    s7comm_plus_item$ts  = network_time();
    s7comm_plus_item$uid = c$uid;
    s7comm_plus_item$id  = c$id;

    s7comm_plus_item$version = version;
    s7comm_plus_item$opcode = fmt("0x%02x", opcode);
    s7comm_plus_item$opcode_name = s7comm_plus_opcodes[opcode];

    if( function_code != UINT16_MAX )
    {
        s7comm_plus_item$function_code = fmt("0x%04x", function_code);
        s7comm_plus_item$function_name = s7comm_plus_functions[function_code];
    }

    Log::write(LOG_S7COMM_PLUS, s7comm_plus_item);
}
