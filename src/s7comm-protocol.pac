## s7comm-protocol.pac
##
## Binpac s7comm Analyzer - Defines Protocol Message Formats
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%include consts.pac

###################################################################################################
#####################################  ZEEK CONNECTION DATA  ######################################
###################################################################################################

## -------------------------------------------S7COMM-PDU-------------------------------------------
## Message Description:
##      Main COTP & S7comm PDU
## Message Format:
##      - tpkt:                 TPKT              -> TPKT Data (see TPKT)
##      - cotp:                 COTP              -> COTP Data (see COTP)
##      - data:                 variable          -> s7comm data or end parsing of current packet
## Protocol Parsing:
##      Starts protocol parsing by getting TPKT and COTP information and passes processing to
##      S7comm_Packet as long as there is data following tpkt and cotp.
## ------------------------------------------------------------------------------------------------
type S7COMM_PDU(is_orig: bool) = record {
    tpkt:               TPKT;
    cotp:               COTP(is_orig);
    data:               case (tpkt.length - cotp.length) of {
        5               -> other:       bytestring &restofdata;
        default         -> s7comm_data: S7comm_Packet(is_orig);
    };
} &let {
    is_originator: bool = is_orig;
} &byteorder=littleendian;

###################################################################################################
##################################  END OF ZEEK CONNECTION DATA  ##################################
###################################################################################################

###################################################################################################
######################################  TPKT & COTP HEADERS  ######################################
###################################################################################################

## ------------------------------------------TPKT-Header-------------------------------------------
## Message Description:
##      TPKT fixed length 4 byte header.
## Message Format:
##      - version:              uint8               -> TPKT Version
##      - reserved:             uint6               -> Reserved (should always be 0)
##      - length:               uint16              -> Length of packet
## Protocol Parsing:
##      Sends header information to the tpkt event. By default this is not logged
## ------------------------------------------------------------------------------------------------
type TPKT = record {
    version:            uint8;
    reserved:           uint8;
    length:             uint16;
} &let {
    deliver: bool = $context.flow.process_tpkt(this);
} &byteorder=bigendian;

## ------------------------------------------COTP-Header-------------------------------------------
## Message Description:
##      COTP header data.
## Message Format:
##      - length:               uint8               -> Length of COTP header
##      - pdu_type:             uint8               -> COTP PDU Type (see cotp_pdu_types in 
##                                                     consts.pac)
##      - cdt:                  uint8               -> CDT (Credit Field)
##      - cotp_data:            variable            -> COTP Data depending on pdu_type
## Protocol Parsing:
##      Sends header information to the cotp event. By default this is then logged to the 
##      cotp.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type COTP(is_orig: bool) = record {
    length:             uint8;
    pdu_data:           uint8;
    cotp_data:          case (pdu_data >> 4) of {
        EXPEDITED_DATA                  -> ed:      COTP_Expedited_Data(length);
        EXPEDITED_DATA_ACKNOWLEDGEMENT  -> ea:      COTP_Expedited_Data_Acknowledgement(length);
        REJECT                          -> rj:      COTP_Reject(length);
        DATA_ACKNOWLEDGEMENT            -> ak:      COTP_Data_Acknowledgement(length);
        TPDU_ERROR                      -> er:      COTP_Error(length);
        DISCONNECT_REQUEST              -> dr:      COTP_Disconnect_Request(length);
        DISCONNECT_CONFIRM              -> dc:      COTP_Disconnect_Confirm(length);
        CONNECTION_CONFIRM              -> cc:      COTP_Connection_Confirm(length);
        CONNECTION_REQUEST              -> cr:      COTP_Connection_Request(length);
        DATA                            -> dt:      COTP_Data(length);
        default                         -> unknown: bytestring &length = length-1;
    };
} &let {
    is_originator:      bool = is_orig;
    pdu_type:           uint8 = (pdu_data >> 4);
    cdt:                uint8 = (pdu_data & 0xf);
    deliver: bool = $context.flow.process_cotp(this);
} &byteorder=littleendian;

###################################################################################################
##################################  END OF TPKT & COTP HEADERS  ###################################
###################################################################################################

###################################################################################################
##################################  S7COMM & S7COMM-PLUS HEADERS  #################################
###################################################################################################

## ------------------------------------------S7comm-Packet-----------------------------------------
## Message Description:
##      S7comm Packet - Differentiate between S7comm or S7comm_Plus
## Message Format:
##      - s7comm_id:            uint8             -> s7comm or s7comm-plus (see consts.pac)
##      - data:                 variable          -> s7comm type depending on s7comm_id
## Protocol Parsing:
##      Passes processing to S7comm or S7comm_Plus according to s7comm_id.
## ------------------------------------------------------------------------------------------------
type S7comm_Packet(is_orig: bool) = record {
    s7comm_id:          uint8;
    data:               case s7comm_id of {
        S7COMM_ID       -> s7comm:      S7comm(is_orig);
        S7COMM_PLUS_ID  -> s7comm_plus: S7comm_Plus(is_orig);
        default         -> other:       bytestring &restofdata;
    };
} &let {
    is_originator: bool = is_orig;
} &byteorder=littleendian;

## -----------------------------------------S7comm-Header------------------------------------------
## Message Description:
##      S7comm header data.
## Message Format:
##      - rosctr:               uint8               -> Length of COTP header
##      - rosctr_function:      variable            -> Rest of S7Comm header is dependant on 
##                                                     ROSCTR so pass functionality depending
##                                                     on ROSCTR
##      - redundancy_id:        uint16              -> Remote Operating Service Control 
##                                                     (see rosctr_types in consts.zeek)
##      - pdu_reference:        uint16              -> Reference ID Used to Link Requests to 
##                                                     Responses
##      - parameter_length:     uint16              -> Length of Parameter following header
##      - data_length:          uint16              -> Length of Data following Parameter 
##      - error_class:          uint8               -> Error Class (see s7comm_error_class in 
##                                                     consts.zeek)
##      - error_code:           uint8               -> Error Code within Error Class
##      - parameter_code:       uint8               -> Parameter Function Code (see 
##                                                     s7comm_functions in consts.zeek)
## Protocol Parsing:
##      Starts protocol parsing for S7comm header by getting ROSCTR then passes processing to
##      ROSCTR specific processing.
## ------------------------------------------------------------------------------------------------
type S7comm(is_orig: bool) = record {
    rosctr:             uint8;
    rosctr_function:    case rosctr of {
        JOB                 -> job:         ROSCTR_Job(is_orig);
        ACK                 -> ack:         ROSCTR_ACK(is_orig);
        ACK_DATA            -> ack_data:    ROSCTR_ACK_Data(is_orig);
        USER_DATA           -> user_data:   ROSCTR_User_Data(is_orig);
        default             -> unknown:     bytestring &restofdata;
    };
} &let {
    is_originator: bool = is_orig;
} &byteorder=bigendian;

## ---------------------------------------S7comm-Plus-Header---------------------------------------
## Message Description:
##      S7comm-plus header data.
## Message Format:
##      - version:              uint8               -> S7comm-plus version
##      - length:               uint16              -> Length of s7comm-plus data
##      - digest_length:        uint8               -> Length of digest portion
##      - digest:               uint8[]             -> Digest portion of s7comm-plus packet
##      - opcode:               uint8               -> Opcode (see s7comm_plus_opcodes in 
##                                                     consts.zeek)
##      - opcode_data:          uint32              -> Additional data found in Opcode 
##                                                     (usually function code)
## Protocol Parsing:
##      Sends header information to the s7comm_plus_header event. By default this is then logged 
##      to the s7comm_plus.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type S7comm_Plus(is_orig: bool) = record {
    version:            uint8;
    length:             uint16;
    digest_length:      uint8;
    digest:             bytestring &length = digest_length;
    opcode:             uint8;
    opcode_data:        uint32;
} &let {
    is_originator: bool = is_orig;
    deliver: bool = $context.flow.process_s7comm_plus_header(this);
} &byteorder=bigendian;

###################################################################################################
###############################  END OF S7COMM & S7COMM-PLUS DATA  ################################
###################################################################################################

###################################################################################################
###################################  S7COMM ROSCTR HEADER DATA  ###################################
###################################################################################################

## -----------------------------------------ROSCTR-Job---------------------------------------------
## Message Description:
##      S7comm header data for ROSCTR Job.
## Message Format:
##      - redundancy_id:        uint16              -> Reserved
##      - pdu_reference:        uint16              -> Reference ID Used to Link Requests to 
##                                                     Responses
##      - parameter_length:     uint16              -> Length of Parameter following header
##      - data_length:          uint16              -> Length of Data following Parameter 
##      - function_code:        uint8               -> Parameter Function Code
##      - function_analysis:    variable            -> If PLC Control, passes processing on to
##                                                     ROSCTR_Job_PLC_Control
## Protocol Parsing:
##      Sends header information to the s7comm_header event. By default this is then logged to the
##      s7comm.log file as defined in main.zeek. If function code is PLC Control, passess 
##      processing to ROSCTR_Job_PLC_Control.
## ------------------------------------------------------------------------------------------------
type ROSCTR_Job(is_orig: bool) = record {
    redundancy_id:      uint16;
    pdu_reference:      uint16;
    parameter_length:   uint16;
    data_length:        uint16;
    function_code:      uint8;
    function_analysis:  case function_code of {
        PLC_CONTROL     -> plc_control:     ROSCTR_Job_PLC_Control(is_orig, pdu_reference);
        default         -> additional_data: bytestring &restofdata;
    };
} &let {
    is_originator: bool = is_orig;
    deliver: bool = $context.flow.process_rosctr_job(this);
} &byteorder=bigendian;

## -------------------------------------ROSCTR-Job-PLC-Control-------------------------------------
## Message Description:
##      S7comm header data for ROSCTR Job with function PLC Control.
## Message Format:
##      - header_h:             uint16              -> Static header (high short)
##      - header_m:             uint8               -> Static header (middle byte)
##      - header_l:             uint32              -> Static header (low int)
##      - block_length:         uint16              -> Length of block (in bytes)
##      - block:                bytestring          -> Additional parameter data
##      - plc_control_length:   uint8               -> Length of PLC Control Name
##      - plc_control_name:     bytestring          -> PLC Control Name
## Protocol Parsing:
##      Sends header information to the s7comm_header event. By default this is then logged to the
##      s7comm.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type ROSCTR_Job_PLC_Control(is_orig: bool, pdu_reference: uint16) = record {
    header_h:           uint16;
    header_m:           uint8;
    header_l:           uint32;
    block_length:       uint16;
    block:              bytestring &length=block_length;
    plc_control_length: uint8;
    plc_control_name:   bytestring &length=plc_control_length;
} &let {
    is_originator: bool = is_orig;
    deliver: bool = $context.flow.process_rosctr_job_plc_control(this);
} &byteorder=bigendian;

## -------------------------------------------ROSCTR-ACK-------------------------------------------
## Message Description:
##      S7comm header data for ROSCTR ACK .
## Message Format:
##      - redundancy_id:        uint16              -> Reserved
##      - pdu_reference:        uint16              -> Reference ID Used to Link Requests to
##                                                     Responses
##      - parameter_length:     uint16              -> Length of Parameter following header
##      - data_length:          uint16              -> Length of Data following Parameter
##      - error_class:          uint8               -> Error Class (see s7comm_error_class in
##                                                     consts.zeek)
##      - error_code:           uint8               -> Error Code within Error Class
##      - additional_data:      bytestring          -> Any trailing data
## Protocol Parsing:
##      Sends header information to the s7comm_header event. By default this is then logged to the
##      s7comm.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type ROSCTR_ACK(is_orig: bool) = record {
    redundancy_id:      uint16;
    pdu_reference:      uint16;
    parameter_length:   uint16;
    data_length:        uint16;
    error_data:         S7Comm_Error;
    function_code:      uint8;
    additional_data:    bytestring &restofdata;
} &let {
    is_originator: bool = is_orig;
    error_class:        uint8 = error_data.error_class;
    error_code:         uint8 = error_data.error_code;
    deliver: bool = $context.flow.process_rosctr_ack(this);
} &byteorder=bigendian;

## -----------------------------------------ROSCTR-ACK-DATA----------------------------------------
## Message Description:
##      S7comm header data for ROSCTR ACK-DATA.
## Message Format:
##      - redundancy_id:        uint16              -> Reserved
##      - pdu_reference:        uint16              -> Reference ID Used to Link Requests to
##                                                     Responses
##      - parameter_length:     uint16              -> Length of Parameter following header
##      - data_length:          uint16              -> Length of Data following Parameter
##      - error_class:          uint8               -> Error Class (see s7comm_error_class in
##                                                     consts.zeek)
##      - error_code:           uint8               -> Error Code within Error Class
##      - function_code:        uint8               -> Parameter Function Code (0xff if none)
##      - additional_data:      bytestring          -> Any trailing data
## Protocol Parsing:
##      Sends header information to the s7comm_header event. By default this is then logged to the
##      s7comm.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type ROSCTR_ACK_Data(is_orig: bool) = record {
    redundancy_id:      uint16;
    pdu_reference:      uint16;
    parameter_length:   uint16;
    data_length:        uint16;
    error_data:         S7Comm_Error;
    parameter:          case parameter_length of {
        0               -> no_parameter:        empty;
        default         -> parameter_data:      uint8;
    };
    additional_data:    bytestring &restofdata;
} &let {
    is_originator: bool = is_orig;
    error_class:        uint8 = error_data.error_class;
    error_code:         uint8 = error_data.error_code;
    function_code:      uint8 = case parameter_length of {
        0               -> 0xff;
        default         -> parameter_data;
    };
    deliver: bool = $context.flow.process_rosctr_ack_data(this);
} &byteorder=bigendian;

## --------------------------------------ROSCTR-User-Data------------------------------------------
## Message Description:
##      S7comm header data for ROSCTR User-Data.
## Message Format:
##      - redundancy_id:        uint16              -> Reserved
##      - pdu_reference:        uint16              -> Reference ID Used to Link Requests to
##                                                     Responses
##      - parameter_length:     uint16              -> Length of Parameter following header
##      - data_length:          uint16              -> Length of Data following Parameter
##      - parameter_head_h:     uint8               -> Parameter head (high byte)
##      - parameter_head_l:     uint16              -> Parameter head (low short)
##      - additional_length:    uint16              -> Length of Additional Parameters
##      - method:               uint8               -> Request or Response
##      - function_code:        uint8               -> Parameter Function Code
##      - subfunction:          uint8               -> Subfunction Code under Function Code
##      - sequence_num:         uint8               -> Sequence Number
##      - request_response      variable            -> Passess processing to either 
##                                                     ROSCTR_User_Data_Response or 
##                                                     ROSCTR_User_Data_Request based on method
## Protocol Parsing:
##      Gets majority of s7comm header information for ROSCTR User-Data functions, then passes 
##      processing to either ROSCTR_User_Data_Response or ROSCTR_User_Data_Request based on method.
## ------------------------------------------------------------------------------------------------
type ROSCTR_User_Data(is_orig: bool) = record {
    redundancy_id:              uint16;
    pdu_reference:              uint16;
    parameter_length:           uint16;
    data_length:                uint16;
    parameter_head_h:           uint8;
    parameter_head_l:           uint16;
    additional_length:          uint8;
    method:                     uint8;
    function_code:              uint8;
    subfunction:                uint8;
    sequence_num:               uint8;
    request_response:           case method of {
        USERDATA_RESPONSE   -> response:       ROSCTR_User_Data_Response(this, is_orig);
        default             -> request:        ROSCTR_User_Data_Request(this, is_orig);
    };
} &let {
    is_originator: bool = is_orig;
} &byteorder=bigendian;

## ----------------------------------ROSCTR-User-Data-Response-------------------------------------
## Message Description:
##      S7comm header data for ROSCTR User-Data-Response.
## Message Format:
##      - data_reference_id:    uint8               -> Data Reference ID to Link multipart packets
##      - last_data_unit:       uint16              -> True or False if last data unit in mutipart
##      - error_code:           uint16              -> Error Code
##      - parameter_data:       variable            -> Passes processing to CPU_Functions if 
##                                                     function code is CPU-Functions
## Protocol Parsing:
##      Sends header information to the s7comm_header event. By default this is then logged to the
##      s7comm.log file as defined in main.zeek. Passes processing to CPU Functions if function
##      code is CPU-Functions.
## ------------------------------------------------------------------------------------------------
type ROSCTR_User_Data_Response(user_data: ROSCTR_User_Data, is_orig: bool) = record {
    data_reference_id:      uint8;
    last_data_unit:         uint8;
    error_code:             uint16;
    parameter_data:             case (user_data.function_code & 0x0f) of {
        0x04                -> cpu_function:    CPU_Functions(user_data, data_reference_id, last_data_unit);
        default             -> unknown:         bytestring &restofdata;
    };
} &let {
    is_originator: bool = is_orig;
    deliver: bool = $context.flow.process_rosctr_user_data_response(this);
} &byteorder=bigendian;

## ----------------------------------ROSCTR-User-Data-Request--------------------------------------
## Message Description:
##      S7comm header data for ROSCTR User-Data-Request.
## Message Format:
##      - parameter_data:       variable            -> Passes processing to CPU_Functions if 
##                                                     function code is CPU-Functions
## Protocol Parsing:
##      Sends header information to the s7comm_header event. By default this is then logged to the
##      s7comm.log file as defined in main.zeek. Passes processing to CPU Functions if function
##      code is CPU-Functions.
## ------------------------------------------------------------------------------------------------
type ROSCTR_User_Data_Request(user_data: ROSCTR_User_Data, is_orig: bool) = record {
    parameter_data:             case (user_data.function_code & 0x0f) of {
        0x04                -> cpu_function:    CPU_Functions(user_data, 0x00, 0x00);
        default             -> unknown:         bytestring &restofdata;
    };
} &let {
    is_originator: bool = is_orig;
    deliver: bool = $context.flow.process_rosctr_user_data_request(this);
} &byteorder=bigendian;

###################################################################################################
###############################  END OF S7COMM ROSCTR HEADER DATA  ################################
###################################################################################################

###################################################################################################
####################################  ADDITIONAL S7COMM DATA  #####################################
###################################################################################################

## ------------------------------------------CPU-Functions-----------------------------------------
## Message Description:
##      ROSCTR CPU-Functions helper.
## Message Format:
##      - subfunction_code:     variable            -> Passes processing to Read_SZL if subfunction
##                                                     is Read SZL
## Protocol Parsing:
##      Passes processing to Read_SZL if subfunction is read_szl.
## ------------------------------------------------------------------------------------------------
type CPU_Functions(user_data: ROSCTR_User_Data, data_reference_id: uint8, last_data_unit: uint8) = record {
    subfunction_code:           case user_data.subfunction of {
        0x01                -> read_szl:        Read_SZL(user_data, data_reference_id, last_data_unit);
        default             -> other:           bytestring &restofdata;
    };
}

## --------------------------------------------READ_SZL--------------------------------------------
## Message Description:
##      S7comm Read SZL data.
## Message Format:
##      - return_code:          uint8               -> Return Code (see 
##                                                     s7comm_userdata_return_codes in consts.zeek)
##      - transport_size:       uint8               -> Transport Size/Type
##      - data_length:          uint16              -> Length of data (in bytes)
##      - szl_id:               uint16              -> SZL ID (see s7comm_szl_id in consts.zeek)
##      - szl_index:            uint16              -> SZL Index
##      - data:                 bytestring          -> Read SZL Data
## Protocol Parsing:
##      Sends read szl information to the s7comm_read_szl event. By default this is then logged to the
##      s7comm_read_szl.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type Read_SZL(user_data: ROSCTR_User_Data, data_reference_id: uint8, last_data_unit: uint8) = record {
    return_code:                uint8;
    transport_size:             uint8;
    data_length:                uint16;
    szl_id:                     uint16;
    szl_index:                  uint16;
    data:                       bytestring &length=data_length-4;
} &let {
    deliver: bool = $context.flow.process_s7comm_read_szl(this);
} &byteorder=bigendian;

## -----------------------------------------S7comm-Error-------------------------------------------
## Message Description:
##      S7comm error data.
## Message Format:
##      - error_class:          uint8               -> Error Class (see s7comm_error_class in
##                                                     consts.zeek)
##      - error_code:           uint8               -> Error Code within Error Class
## Protocol Parsing:
##      Helper record for S7comm header parsing.
## ------------------------------------------------------------------------------------------------
type S7Comm_Error = record {
    error_class:        uint8;
    error_code:         uint8;
} &byteorder=bigendian;

###################################################################################################
################################# END OF ADDITIONAL S7COMM DATA  ##################################
###################################################################################################

###################################################################################################
###################################  COTP TYPES USED IN S7COMM  ###################################
###################################################################################################

## ------------------------------------------COTP-Data---------------------------------------------
## Message Description:
##      COTP Data.
## Protocol Parsing:
##      Sends header information to the cotp_data event. By default this is not logged.
## ------------------------------------------------------------------------------------------------
type COTP_Data(length: uint8) = record {
    tpdu_and_eot:       uint8;
    variable_data:      bytestring &length = length-2;
} &let {
    tpdu_sequence_num:  uint8 = tpdu_and_eot & 0x7f;
    eot:                uint8 = tpdu_and_eot >> 7;
    deliver: bool = $context.flow.process_cotp_data(this);
} &byteorder=bigendian;

## ------------------------------------COTP-Connection-Request-------------------------------------
## Message Description:
##      COTP Connection Request.
## Protocol Parsing:
##      Sends header information to the cotp_connection_request event. By default this is not 
##      logged.
## ------------------------------------------------------------------------------------------------
type COTP_Connection_Request(length: uint8) = record {
    dst_reference:      uint16;
    src_reference:      uint16;
    class_and_option:   uint8;
    variable_data:      bytestring &length = length-6;
} &let {
    class_id:               uint8 = class_and_option >> 4;
    extended_format:        uint8 = (class_and_option >> 1) & 0x1;
    explicit_flow_control:  uint8 = class_and_option & 0x1;
    deliver: bool = $context.flow.process_cotp_connection_request(this);
} &byteorder=bigendian;

## ------------------------------------COTP-Connection-Confirm-------------------------------------
## Message Description:
##      COTP Connection Confirm.
## Protocol Parsing:
##      Sends header information to the cotp_connection_confirm event. By default this is not 
##      logged.
## ------------------------------------------------------------------------------------------------
type COTP_Connection_Confirm(length: uint8) = record {
    dst_reference:      uint16;
    src_reference:      uint16;
    class_and_option:   uint8;
    variable_data:      bytestring &length = length-6;
} &let {
    class_id:               uint8 = class_and_option >> 4;
    extended_format:        uint8 = (class_and_option >> 1) & 0x1;
    explicit_flow_control:  uint8 = class_and_option & 0x1;
    deliver: bool = $context.flow.process_cotp_connection_confirm(this);
} &byteorder=bigendian;

###################################################################################################
################################  END OF COTP TYPES USED IN S7COMM  ###############################
###################################################################################################

###################################################################################################
#############################  OTHER COTP TYPES (NOT USED IN S7COMM)  #############################
###################################################################################################

## ------------------------------------COTP-Disconnect-Request-------------------------------------
## Message Description:
##      COTP Disconnect Request.
## Protocol Parsing:
##      Sends header information to the cotp_disconnect_request event. By default this is not 
##      logged.
## ------------------------------------------------------------------------------------------------
type COTP_Disconnect_Request(length: uint8) = record {
    dst_reference:      uint16;
    src_reference:      uint16;
    reason:             uint8;
    variable_data:      bytestring &length = length-6;
} &let {
    deliver: bool = $context.flow.process_cotp_disconnect_request(this);
} &byteorder=bigendian;

## ------------------------------------COTP-Disconnect-Confirm-------------------------------------
## Message Description:
##      COTP Disconnect Confirm.
## Protocol Parsing:
##      Sends header information to the cotp_disconnect_confirm event. By default this is not 
##      logged.
## ------------------------------------------------------------------------------------------------
type COTP_Disconnect_Confirm(length: uint8) = record {
    dst_reference:      uint16;
    src_reference:      uint16;
    variable_data:      bytestring &length = length-5;
} &let {
    deliver: bool = $context.flow.process_cotp_disconnect_confirm(this);
} &byteorder=bigendian;

## --------------------------------------COTP-Expedited-Data---------------------------------------
## Message Description:
##      COTP Expedited Data.
## Protocol Parsing:
##      Sends header information to the cotp_expedited_data event. By default this is not logged.
## ------------------------------------------------------------------------------------------------
type COTP_Expedited_Data(length: uint8) = record {
    dst_reference:      uint16;
    tpdu_and_eot:       uint8;
    variable_data:      bytestring &length = length-4;
} &let {
    tpdu_id:            uint8 = tpdu_and_eot & 0x7f;
    eot:                uint8 = tpdu_and_eot >> 7;
    deliver: bool = $context.flow.process_cotp_expedited_data(this);
} &byteorder=bigendian;

## -----------------------------------COTP-Data-Acknowledgement------------------------------------
## Message Description:
##      COTP Data Acknowledgement.
## Protocol Parsing:
##      Sends header information to the cotp_data_acknowledgement event. By default this is not 
##      logged.
## ------------------------------------------------------------------------------------------------
type COTP_Data_Acknowledgement(length: uint8) = record {
    dst_reference:      uint16;
    next_tpdu:          uint8;
    variable_data:      bytestring &length = length-4;
} &let {
    deliver: bool = $context.flow.process_cotp_data_acknowledgement(this);
} &byteorder=bigendian;

## ------------------------------COTP-Expedited-Data-Acknowledgement-------------------------------
## Message Description:
##      COTP Expedited Data Acknowledgement.
## Protocol Parsing:
##      Sends header information to the cotp_expedited_data_acknowledgement event. By default this
##      is not logged.
## ------------------------------------------------------------------------------------------------
type COTP_Expedited_Data_Acknowledgement(length: uint8) = record {
    dst_reference:      uint16;
    tpdu_id:            uint8;
    variable_data:      bytestring &length = length-4;
} &let {
    deliver: bool = $context.flow.process_cotp_expedited_data_acknowledgement(this);
} &byteorder=bigendian;

## ------------------------------------------COTP-Reject-------------------------------------------
## Message Description:
##      COTP Reject.
## Protocol Parsing:
##      Sends header information to the cotp_reject event. By default this is not logged.
## ------------------------------------------------------------------------------------------------
type COTP_Reject(length: uint8) = record {
    dst_reference:      uint16;
    next_tpdu:          uint8;
    variable_data:      bytestring &length = length-4;
} &let {
    deliver: bool = $context.flow.process_cotp_reject(this);
} &byteorder=bigendian;

## -------------------------------------------COTP-Error-------------------------------------------
## Message Description:
##      COTP Error.
## Protocol Parsing:
##      Sends header information to the cotp_error event. By default this is not logged.
## ------------------------------------------------------------------------------------------------
type COTP_Error(length: uint8) = record {
    dst_reference:      uint16;
    error_code:         uint8;
    variable_data:      bytestring &length = length-4;
} &let {
    deliver: bool = $context.flow.process_cotp_error(this);
} &byteorder=bigendian;

###################################################################################################
##########################  END OF OTHER COTP TYPES (NOT USED IN S7COMM)  #########################
###################################################################################################