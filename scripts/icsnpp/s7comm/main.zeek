##! main.zeek
##!
##! Binpac s7comm Analyzer - Contains the base script-layer functionality for
##!                          processing events emitted from the analyzer.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module S7COMM;

export{
    redef enum Log::ID += { LOG_COTP, 
                            LOG_S7COMM, 
                            LOG_S7COMM_READ_SZL, 
                            LOG_S7COMM_UPLOAD_DOWNLOAD, 
                            LOG_S7COMM_PLUS };

    ###############################################################################################
    #####################################  COTP -> cotp.log  ######################################
    ###############################################################################################
    type COTP: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
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
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        rosctr_code             : count     &log;   # Remote Operating Service Control Code (in hex)
        rosctr_name             : string    &log;   # Remote Operating Service Control Name
        pdu_reference           : count     &log;   # Reference ID Used to Link Requests to Responses
        function_code           : string    &log;   # Parameter Function Code (in hex)
        function_name           : string    &log;   # Parameter Function Name
        subfunction_code        : string    &log;   # User-Data Subfunction Code (in hex)
        subfunction_name        : string    &log;   # User-Data Subfunction Name
        error_class             : string    &log;   # Error Class Name
        error_code              : string    &log;   # Error Code within Error Class
    };
    global log_s7comm: event(rec: S7COMM);

    ###############################################################################################
    ##########################  S7COMM_READ_SZL -> s7comm_read_szl.log  ###########################
    ###############################################################################################
    type S7COMM_READ_SZL: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        pdu_reference           : count     &log;   # Reference ID Used to Link Requests to Responses
        method                  : string    &log;   # Request or Response
        szl_id                  : string    &log;   # SZL ID (in hex)
        szl_id_name             : string    &log;   # Meaning of SZL ID
        szl_index               : string    &log;   # SZL Index (in hex)
        return_code             : string    &log;   # Return Code (in hex)
        return_code_name        : string    &log;   # Meaning of Return Code
    };
    global log_s7comm_read_szl: event(rec: S7COMM_READ_SZL);

    ###############################################################################################
    ###################  S7COMM_UPLOAD_DOWNLOAD -> s7comm_upload_download.log  ####################
    ###############################################################################################
    type S7COMM_UPLOAD_DOWNLOAD: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        rosctr                  : string    &log;   # Remote Operating Service Control Name
        pdu_reference           : count     &log;   # Reference ID Used to Link Requests to Responses
        function_name           : string    &log;   # Upload/Download Function Name
        function_status         : string    &log;   # Function Return Status
        session_id              : count     &log;   # Session ID
        blocklength             : count     &log;   # Length of Block to Upload/Download
        filename                : string    &log;   # Filename to Upload/Download
        block_type              : string    &log;   # Block Type to Upload/Download
        block_number            : string    &log;   # Block Number to Upload/Download
        destination_filesystem  : string    &log;   # Destination Filesystem to Upload/Download
    };
    global log_s7comm_upload_download: event(rec: S7COMM_UPLOAD_DOWNLOAD);

    ###############################################################################################
    ###############################  S7COMM_PLUS -> s7comm_plus.log  ##############################
    ###############################################################################################
    type S7COMM_PLUS: record {
        ts                      : time      &log;   # Timestamp of Event
        uid                     : string    &log;   # Zeek Unique ID for Connection
        id                      : conn_id   &log;   # Zeek Connection Struct (addresses and ports)
        is_orig                 : bool      &log;   # the message came from the originator/client or the responder/server
        source_h                : addr      &log;   # Source IP Address
        source_p                : port      &log;   # Source Port
        destination_h           : addr      &log;   # Destination IP Address
        destination_p           : port      &log;   # Destination Port
        version                 : count     &log;   # S7comm-plus Version
        opcode                  : string    &log;   # Opcode Code (in hex)
        opcode_name             : string    &log;   # Opcode Name
        function_code           : string    &log;   # Opcode Function Code (in hex)
        function_name           : string    &log;   # Opcode Function Name
    };
    global log_s7comm_plus: event(rec: S7COMM_PLUS);

    redef record connection += {
        filename    : string &optional;
    };
}

# All these protocols operate on TCP port 102
const ports = {
    102/tcp,
};
redef likely_server_ports += { ports };

###################################################################################################
####  Defines Log Streams for cotp.log, s7comm.log, s7comm_read_szl.log, and s7comm_plus.log  #####
###################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(S7COMM::LOG_COTP, [$columns=COTP,
                                          $ev=log_cotp,
                                          $path="cotp"]);

    Log::create_stream(S7COMM::LOG_S7COMM, [$columns=S7COMM,
                                            $ev=log_s7comm,
                                            $path="s7comm"]);

    Log::create_stream(S7COMM::LOG_S7COMM_READ_SZL, [$columns=S7COMM_READ_SZL,
                                            $ev=log_s7comm_read_szl,
                                            $path="s7comm_read_szl"]);

    Log::create_stream(S7COMM::LOG_S7COMM_UPLOAD_DOWNLOAD, [$columns=S7COMM_UPLOAD_DOWNLOAD,
                                            $ev=log_s7comm_upload_download,
                                            $path="s7comm_upload_download"]);

    Log::create_stream(S7COMM::LOG_S7COMM_PLUS, [$columns=S7COMM_PLUS,
                                            $ev=log_s7comm_plus,
                                            $path="s7comm_plus"]);

    # Analyzer::register_for_ports(Analyzer::ANALYZER_S7COMM_TCP, ports);
}

###################################################################################################
###########################  Defines logging of cotp event -> cotp.log  ###########################
###################################################################################################
event cotp(c: connection,
           is_orig: bool,
           pdu: count) {

    add c$service["cotp"];
    local cotp_item: COTP;
    cotp_item$ts  = network_time();
    cotp_item$uid = c$uid;
    cotp_item$id  = c$id;
    cotp_item$is_orig  = is_orig;

    if(is_orig)
    {
        cotp_item$source_h = c$id$orig_h;
        cotp_item$source_p = c$id$orig_p;
        cotp_item$destination_h = c$id$resp_h;
        cotp_item$destination_p = c$id$resp_p;
    }else
    {
        cotp_item$source_h = c$id$resp_h;
        cotp_item$source_p = c$id$resp_p;
        cotp_item$destination_h = c$id$orig_h;
        cotp_item$destination_p = c$id$orig_p;
    }

    cotp_item$pdu_code = fmt("0x%02x", pdu);
    cotp_item$pdu_name = cotp_pdu_types[pdu];

    Log::write(LOG_COTP, cotp_item);
}

###################################################################################################
#####################  Defines logging of s7comm_header event -> s7comm.log  ######################
###################################################################################################
event s7comm_header(c: connection,
                    is_orig: bool,
                    rosctr: count,
                    pdu_reference: count,
                    function_code: count,
                    subfunction: count,
                    plc_control: string,
                    error_class: count,
                    error_code: count) {

    add c$service["s7comm"];
    local s7comm_item: S7COMM;

    s7comm_item$ts  = network_time();
    s7comm_item$uid = c$uid;
    s7comm_item$id  = c$id;
    s7comm_item$is_orig  = is_orig;

    if(is_orig)
    {
        s7comm_item$source_h = c$id$orig_h;
        s7comm_item$source_p = c$id$orig_p;
        s7comm_item$destination_h = c$id$resp_h;
        s7comm_item$destination_p = c$id$resp_p;
    }else
    {
        s7comm_item$source_h = c$id$resp_h;
        s7comm_item$source_p = c$id$resp_p;
        s7comm_item$destination_h = c$id$orig_h;
        s7comm_item$destination_p = c$id$orig_p;
    }

    s7comm_item$rosctr_code = rosctr;
    s7comm_item$rosctr_name = rosctr_types[rosctr];
    s7comm_item$pdu_reference = pdu_reference;

    if ( function_code != UINT8_MAX )
    {
        # Formatting for function is different for User-Data functions
        if ( rosctr == 0x07 ) 
        {
            s7comm_item$function_code = fmt("0x%02x", function_code);
            if ( (function_code & 0xf0) == 0x40)
                s7comm_item$function_name = "Request: " + s7comm_userdata_functions[function_code & 0x0f];
            else if ( (function_code & 0xf0) == 0x80)
                s7comm_item$function_name = "Response: " + s7comm_userdata_functions[function_code & 0x0f];
            else if ( (function_code & 0xf0) == 0x00)
                s7comm_item$function_name = "Push: " + s7comm_userdata_functions[function_code & 0x0f];
            else
                s7comm_item$function_name = "Unknown: " + s7comm_userdata_functions[function_code & 0x0f];
        }
        else
        {
            s7comm_item$function_code = fmt("0x%02x", function_code);
            s7comm_item$function_name = s7comm_functions[function_code];
        }
    }
 
    if ( subfunction != UINT8_MAX )
    {
        s7comm_item$subfunction_code = fmt("0x%02x", subfunction);

        # For User-data functions, subfunction code and name is dependant on function code
        switch( (function_code & 0x0f) )
        {
            case 0x00:
                s7comm_item$subfunction_name = s7comm_mode_transition_subfunctions[subfunction];
                break;
            case 0x01:
                s7comm_item$subfunction_name = s7comm_programmer_controls_subfunctions[subfunction];
                break;
            case 0x02:
                s7comm_item$subfunction_name = s7comm_cyclic_services_subfunctions[subfunction];
                break;
            case 0x03:
                s7comm_item$subfunction_name = s7comm_block_functions_subfunctions[subfunction];
                break;
            case 0x04:
                s7comm_item$subfunction_name = s7comm_cpu_functions_subfunctions[subfunction];
                break;
            case 0x05:
                s7comm_item$subfunction_name = s7comm_security_subfunctions[subfunction];
                break;
            case 0x07:
                s7comm_item$subfunction_name = s7comm_time_functions_subfunctions[subfunction];
                break;
            default:
                break;
        }
    }

    # For PLC Control messages, add PLC Control services to subfunction name
    if ( function_code == 0x28 && rosctr == 0x01 )
    {
        s7comm_item$subfunction_code = plc_control;
        s7comm_item$subfunction_name = s7comm_plc_control_services[plc_control];
    }

    # Print error classes and error codes if they exist
    if ( error_code != UINT8_MAX && error_code != UINT16_MAX )
    {
        if ( error_class != 0xfe )
        {
            s7comm_item$error_class = s7comm_error_class[error_class];
            s7comm_item$error_code = fmt("0x%02x", error_code);
        }
        else if ( error_code == 0x00 )
        {
            s7comm_item$error_class = s7comm_error_class[0x00];
            s7comm_item$error_code = fmt("0x%02x", error_code);
        }
        else
        {
            s7comm_item$error_class = "Parameter Error";
            s7comm_item$error_code = fmt("0x%02x", error_code);
        }
    }

    Log::write(LOG_S7COMM, s7comm_item);
}

###################################################################################################
################  Defines logging of s7comm_read_szl event -> s7comm_read_szl.log  ################
###################################################################################################
event s7comm_read_szl(c: connection,
                      is_orig: bool,
                      pdu_reference: count,
                      method: count,
                      return_code: count,
                      szl_id: count,
                      szl_index: count) {

    local s7comm_read_szl_item: S7COMM_READ_SZL;

    s7comm_read_szl_item$ts  = network_time();
    s7comm_read_szl_item$uid = c$uid;
    s7comm_read_szl_item$id  = c$id;
    s7comm_read_szl_item$is_orig  = is_orig;

    if(is_orig)
    {
        s7comm_read_szl_item$source_h = c$id$orig_h;
        s7comm_read_szl_item$source_p = c$id$orig_p;
        s7comm_read_szl_item$destination_h = c$id$resp_h;
        s7comm_read_szl_item$destination_p = c$id$resp_p;
    }else
    {
        s7comm_read_szl_item$source_h = c$id$resp_h;
        s7comm_read_szl_item$source_p = c$id$resp_p;
        s7comm_read_szl_item$destination_h = c$id$orig_h;
        s7comm_read_szl_item$destination_p = c$id$orig_p;
    }

    s7comm_read_szl_item$pdu_reference = pdu_reference;
    s7comm_read_szl_item$method = s7comm_userdata_method[method];
    s7comm_read_szl_item$szl_id = fmt("0x%04x", szl_id);
    s7comm_read_szl_item$szl_id_name = s7comm_szl_id[szl_id & 0xff];
    s7comm_read_szl_item$szl_index = fmt("0x%04x", szl_index);
    s7comm_read_szl_item$return_code = fmt("0x%02x", return_code);
    s7comm_read_szl_item$return_code_name = s7comm_userdata_return_codes[return_code];

    Log::write(LOG_S7COMM_READ_SZL, s7comm_read_szl_item);
}

###################################################################################################
#########  Defines logging of s7comm_upload_download event -> s7comm_upload_download.log  #########
###################################################################################################

event s7comm_upload_download(c: connection,
                             is_orig: bool,
                             rosctr: count,
                             pdu_reference: count,
                             function_code: count,
                             function_status: count,
                             session_id: count,
                             blocklength: count,
                             filename: string,
                             block_type: string,
                             block_number: string,
                             destination_filesystem: string) {

    local s7comm_upload_download_item: S7COMM_UPLOAD_DOWNLOAD;

    s7comm_upload_download_item$ts  = network_time();
    s7comm_upload_download_item$uid = c$uid;
    s7comm_upload_download_item$id  = c$id;
    s7comm_upload_download_item$is_orig  = is_orig;

    if(is_orig)
    {
        s7comm_upload_download_item$source_h = c$id$orig_h;
        s7comm_upload_download_item$source_p = c$id$orig_p;
        s7comm_upload_download_item$destination_h = c$id$resp_h;
        s7comm_upload_download_item$destination_p = c$id$resp_p;
    }else
    {
        s7comm_upload_download_item$source_h = c$id$resp_h;
        s7comm_upload_download_item$source_p = c$id$resp_p;
        s7comm_upload_download_item$destination_h = c$id$orig_h;
        s7comm_upload_download_item$destination_p = c$id$orig_p;
    }

    s7comm_upload_download_item$rosctr = rosctr_types[rosctr];
    s7comm_upload_download_item$pdu_reference = pdu_reference;
    s7comm_upload_download_item$function_name = s7comm_functions[function_code];
    
    if ( function_status != UINT8_MAX )
        s7comm_upload_download_item$function_status = fmt("0x%02x", function_status);

    if ( session_id != UINT32_MAX )
        s7comm_upload_download_item$session_id = session_id;

    if ( blocklength != UINT16_MAX )
        s7comm_upload_download_item$blocklength = blocklength;

    if ( filename != "" )
    {
        c$filename = filename;
        s7comm_upload_download_item$filename = filename;
        s7comm_upload_download_item$block_type = s7comm_block_types[block_type];
        s7comm_upload_download_item$block_number = block_number;
        s7comm_upload_download_item$destination_filesystem = s7comm_destination_filesystem[destination_filesystem];
    }

    Log::write(LOG_S7COMM_UPLOAD_DOWNLOAD, s7comm_upload_download_item);
}

###################################################################################################
#################  Defines logging of s7comm_plus_header event -> s7comm_plus.log  ################
###################################################################################################
event s7comm_plus_header(c: connection,
                         is_orig: bool,
                         version: count,
                         opcode: count,
                         function_code: count) {

    add c$service["s7comm-plus"];
    local s7comm_plus_item: S7COMM_PLUS;

    s7comm_plus_item$ts  = network_time();
    s7comm_plus_item$uid = c$uid;
    s7comm_plus_item$id  = c$id;
    
    s7comm_plus_item$is_orig  = is_orig;

    if(is_orig)
    {
        s7comm_plus_item$source_h = c$id$orig_h;
        s7comm_plus_item$source_p = c$id$orig_p;
        s7comm_plus_item$destination_h = c$id$resp_h;
        s7comm_plus_item$destination_p = c$id$resp_p;
    }else
    {
        s7comm_plus_item$source_h = c$id$resp_h;
        s7comm_plus_item$source_p = c$id$resp_p;
        s7comm_plus_item$destination_h = c$id$orig_h;
        s7comm_plus_item$destination_p = c$id$orig_p;
    }

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
