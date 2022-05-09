##! consts.zeek
##!
##! Binpac s7comm Analyzer - Defines s7comm, s7comm-plus, and COTP constants for main.zeek
##!
##! Author:  Stephen Kleinheider
##! Contact: stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module S7COMM;

export {
    const UINT32_MAX = 0xFFFFFFFF;
    const UINT16_MAX = 0xFFFF;

    ###############################################################################################
    ######################################  COTP PDU Types  #######################################
    ###############################################################################################
    const cotp_pdu_types = {
        [0x1] = "ED Expedited Data",
        [0x2] = "EA Expedited Data Acknowledgement",
        [0x5] = "RJ Reject",
        [0x6] = "AK Data Acknowledgement",
        [0x7] = "ER TPDU Error",
        [0x8] = "DR Disconnect Request",
        [0xc] = "DC Disconnect Confirm",
        [0xd] = "CC Connection Confirm",
        [0xe] = "CR Connection Request",
        [0xf] = "DT Data",
    } &default = function(n: count): string {return fmt("Unknown COTP PDU-0x%02x", n); };

    ###############################################################################################
    ######################  S7comm Remote Operating Service Control (ROSCTR)  #####################
    ###############################################################################################
    const rosctr_types = {
        [0x01] = "Job Request",
        [0x02] = "ACK",
        [0x03] = "ACK Data",
        [0x07] = "User Data",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ######################  S7comm Remote Operating Service Control (ROSCTR)  #####################
    ###############################################################################################
    const s7comm_error_class = {
        [0x00] = "No error",
        [0x81] = "Application relationship error",
        [0x82] = "Object definition error",
        [0x83] = "No ressources available error",
        [0x84] = "Error on service processing",
        [0x85] = "Error on supplies",
        [0x87] = "Access error",
    } &default = function(n: count): string {return fmt("Unknown error class-0x%02x", n); };

    ###############################################################################################
    #################################  S7comm Parameter Functions  ################################
    ###############################################################################################
    const s7comm_functions = {
        [0x00] = "CPU services",
        [0x04] = "Read Variable",
        [0x05] = "Write Variable",
        [0x1a] = "Request download",
        [0x1b] = "Download block",
        [0x1c] = "Download ended",
        [0x1d] = "Start upload",
        [0x1e] = "Upload",
        [0x1f] = "End upload",
        [0x28] = "PLC Control",
        [0x29] = "PLC Stop",
        [0xf0] = "Setup communication",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ####################################  S7comm-plus Opcodes  ####################################
    ###############################################################################################
    const s7comm_plus_opcodes = {
        [0x31] = "Request",
        [0x32] = "Response",
        [0x33] = "Notification"
    } &default = function(n: count): string {return fmt("Unknown s7comm-plus opcode-0x%02x", n); };

    ###############################################################################################
    #############################  S7comm-plus Opcode Data Functions  #############################
    ###############################################################################################
    const s7comm_plus_functions = {
        [0x04bb] = "Explore",
        [0x04ca] = "Create Object",
        [0x04d4] = "Delete Object",
        [0x04f2] = "Set Variable",
        [0x0524] = "Get Link",
        [0x0542] = "Set Multi Variables",
        [0x054c] = "Get Multi Variables",
        [0x0556] = "Begin Sequence",
        [0x0560] = "End Sequence",
        [0x056b] = "Invoke",
        [0x0586] = "Get Variable Sub Streamed"
    } &default = function(n: count): string {return fmt("Unknown s7comm-plus function-0x%04x", n); };
}