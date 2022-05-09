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
##      - s7comm_id:            uint8             -> s7comm or s7comm-plus (see consts.pac)
##      - data:                 variable          -> s7comm type depending on s7comm_id
## Protocol Parsing:
##      Starts protocol parsing by getting TPKT and COTP information and passes proccessing to
##      S7comm or S7comm_Plus according to s7comm_id.
## ------------------------------------------------------------------------------------------------
type S7COMM_PDU(is_orig: bool) = record {
    tpkt:               TPKT;
    cotp:               COTP;
    s7comm_id:          uint8;
    data:               case s7comm_id of {
        S7COMM_ID       -> s7comm:      S7comm;
        S7COMM_PLUS_ID  -> s7comm_plus: S7comm_Plus;
        default         -> other:       bytestring &restofdata;
    };
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
type COTP = record {
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
    pdu_type:           uint8 = (pdu_data >> 4);
    cdt:                uint8 = (pdu_data & 0xf);
    deliver: bool = $context.flow.process_cotp(this);
} &byteorder=littleendian;

###################################################################################################
##################################  END OF TPKT & COTP HEADERS  ###################################
###################################################################################################

###################################################################################################
###################################  S7COMM & S7COMM-PLUS DATA  ###################################
###################################################################################################


## -----------------------------------------S7comm-Header------------------------------------------
## Message Description:
##      S7comm header data.
## Message Format:
##      - rosctr:               uint8               -> Length of COTP header
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
##      Sends header information to the s7comm_header event. By default this is then logged to the 
##      s7comm.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type S7comm = record {
    rosctr:             uint8;
    redundancy_id:      uint16;
    pdu_reference:      uint16;
    parameter_length:   uint16;
    data_length:        uint16;
    error:              case rosctr of {
        ACK, ACK_DATA   -> error_data:          S7Comm_Error;
        default         -> no_error_data:       empty;
    };
    parameter:          case parameter_length of {
        0               -> no_parameter:        empty;
        default         -> parameter_data:      uint8;
    };
    parameter_and_data: bytestring &restofdata;
    # Future work - parse out these parameters and data
} &let {
    error_class:        uint8   = case rosctr of {
        ACK, ACK_DATA   -> error_data.error_class;
        default         -> 0xff;
    };
    error_code:         uint8   = case rosctr of {
        ACK, ACK_DATA   -> error_data.error_code;
        default         -> 0xff;
    };
    parameter_code:     uint8   = case parameter_length of {
        0               -> 0xff;
        default         -> parameter_data;
    };
    deliver: bool = $context.flow.process_s7comm_header(this);
} &byteorder=bigendian;

## -----------------------------------------S7comm-Error-------------------------------------------
## Message Description:
##      S7comm error data.
## Protocol Parsing:
##      Helper record for S7comm header parsing.
## ------------------------------------------------------------------------------------------------
type S7Comm_Error = record {
    error_class:        uint8;
    error_code:         uint8;
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
type S7comm_Plus = record {
    version:            uint8;
    length:             uint16;
    digest_length:      uint8;
    digest:             bytestring &length = digest_length;
    opcode:             uint8;
    opcode_data:        uint32;
} &let {
    deliver: bool = $context.flow.process_s7comm_plus_header(this);
} &byteorder=bigendian;

###################################################################################################
###############################  END OF S7COMM & S7COMM-PLUS DATA  ################################
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