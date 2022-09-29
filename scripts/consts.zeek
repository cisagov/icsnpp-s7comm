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
    const UINT8_MAX = 0xFF;

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
        [0x01] = "Job-Request",
        [0x02] = "ACK",
        [0x03] = "ACK-Data",
        [0x07] = "User-Data",
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
        [0x00] = "CPU Services",
        [0x04] = "Read Variable",
        [0x05] = "Write Variable",
        [0x1a] = "Request Download",
        [0x1b] = "Download Block",
        [0x1c] = "Download Ended",
        [0x1d] = "Start Upload",
        [0x1e] = "Upload",
        [0x1f] = "End Upload",
        [0x28] = "PLC Control",
        [0x29] = "PLC Stop",
        [0xf0] = "Setup Communication",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ################################  S7comm User-Data Functions  #################################
    ###############################################################################################
    const s7comm_userdata_functions = {
        [0x00] = "Mode-Transition",
        [0x01] = "Programmer Controls",
        [0x02] = "Cyclic Services",
        [0x03] = "Block Functions",
        [0x04] = "CPU Functions",
        [0x05] = "Security",
        [0x06] = "PBC BSEND-BRECV",
        [0x07] = "Time Functions",
        [0x0f] = "NC Programming",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ######################  S7comm User-Data Mode Transition Sub-Functions  #######################
    ###############################################################################################
    const s7comm_mode_transition_subfunctions = {
        [0x00] = "Stop",
        [0x01] = "Warm Restart",
        [0x02] = "Run",
        [0x03] = "Hot Restart",
        [0x04] = "Hold",
        [0x06] = "Cold Restart",
        [0x09] = "Run_R",
        [0x0b] = "Link-Up",
        [0x0c] = "Update",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ###################  S7comm User-Data Programmer Controls Sub-Functions  ######################
    ###############################################################################################
    const s7comm_programmer_controls_subfunctions = {
        [0x01] = "Block Status",
        [0x02] = "Variable Status",
        [0x03] = "Output ISTACK",
        [0x04] = "Output BSTACK",
        [0x05] = "Output LSTACK",
        [0x06] = "Time Measurement",
        [0x07] = "Force Selection",
        [0x08] = "Modify Variable",
        [0x09] = "Force",
        [0x0a] = "Breakpoint",
        [0x0b] = "Exit HOLD",
        [0x0c] = "Memory Reset",
        [0x0d] = "Disable Job",
        [0x0e] = "Enable Job",
        [0x0f] = "Delete Job",
        [0x10] = "Read Job List",
        [0x11] = "Read Job",
        [0x12] = "Replace Job",
        [0x13] = "Block Status v2",
        [0x16] = "Flash LED",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ######################  S7comm User-Data Cyclic Services Sub-Functions  #######################
    ###############################################################################################
    const s7comm_cyclic_services_subfunctions = {
        [0x01] = "Cyclic Transfer",
        [0x04] = "Unsubscribe",
        [0x05] = "Change Driven Transfer",
        [0x07] = "Change Driven Transfer Modify",
        [0x08] = "RDREC",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    #######################  S7comm User-Data Block Functions Sub-Functions  ######################
    ###############################################################################################
    const s7comm_block_functions_subfunctions = {
        [0x01] = "List Blocks",
        [0x02] = "List Blocks of Type",
        [0x03] = "Get Block Info",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ########################  S7comm User-Data CPU Functions Sub-Functions  #######################
    ###############################################################################################
    const s7comm_cpu_functions_subfunctions = {
        [0x01] = "Read SZL",
        [0x02] = "Message Service",
        [0x03] = "Diagnostic Message",
        [0x04] = "ALARM_8 Indication",
        [0x05] = "NOTIFY Indication",
        [0x06] = "ALARM_8 Lock",
        [0x07] = "ALARM_8 Unlock",
        [0x08] = "SCAN Indication",
        [0x0b] = "ALARM_S Indication",
        [0x0c] = "ALARM_SQ Indication",
        [0x0d] = "ALARM Query",
        [0x0e] = "ALARM ACK",
        [0x11] = "ALARM ACK Indication",
        [0x12] = "ALARM Lock Indication",
        [0x13] = "ALARM Unlock Indication",
        [0x16] = "NOTIFY_8 Indication",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    ##########################  S7comm User-Data Security Sub-Functions  ##########################
    ###############################################################################################
    const s7comm_security_subfunctions = {
        [0x01] = "PLC Password",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    #######################  S7comm User-Data Time Functions Sub-Functions  #######################
    ###############################################################################################
    const s7comm_time_functions_subfunctions = {
        [0x01] = "Read Clock",
        [0x02] = "Set Clock",
        [0x03] = "Read Clock (Following)",
        [0x04] = "Set Clock (2)",
    } &default = function(n: count): string {return "unknown";};

    ###############################################################################################
    #######################  S7comm User-Data Methods (Request or Response)  ######################
    ###############################################################################################
    const s7comm_userdata_method = {
        [0x11] = "Request",
        [0x12] = "Response",
    } &default = function(n: count): string {return "Unknown"; };

    ###############################################################################################
    ###############################  S7comm User-Data Return Codes  ###############################
    ###############################################################################################
    const s7comm_userdata_return_codes = {
        [0x00] = "Reserved",
        [0x01] = "Hardware error",
        [0x03] = "Accessing the bbject not allowed",
        [0x05] = "Invalid address",
        [0x06] = "Data type not supported",
        [0x07] = "Data type inconsistent",
        [0x0a] = "Object does not exist",
        [0xff] = "Success",
    } &default = function(n: count): string {return "Unknown"; };

    ###############################################################################################
    ##################################  S7comm SZL ID Meanings   ##################################
    ###############################################################################################
    const s7comm_szl_id = {
        [0x00] = "List of all the SZL-IDs of a module",
        [0x11] = "Module identification",
        [0x12] = "CPU characteristics",
        [0x13] = "User memory areas",
        [0x14] = "System areas",
        [0x15] = "Block types",
        [0x16] = "Priority classes",
        [0x17] = "List of the permitted SDBs with a number < 1000",
        [0x18] = "Maximum S7-300 I/O configuration",
        [0x19] = "Status of the module LEDs",
        [0x1c] = "Component Identification",
        [0x21] = "Interrupt / error assignment",
        [0x22] = "Interrupt status",
        [0x23] = "Priority classes",
        [0x24] = "Modes",
        [0x25] = "Assignment between process image partitions and OBs",
        [0x31] = "Communication capability parameters",
        [0x32] = "Communication status data",
        [0x33] = "Diagnostics: device logon list",
        [0x37] = "Ethernet - Details of a Module",
        [0x71] = "H CPU group information",
        [0x74] = "Status of the module LEDs",
        [0x75] = "Switched DP slaves in the H-system",
        [0x81] = "Start information list",
        [0x82] = "Start event list",
        [0x91] = "Module status information",
        [0x92] = "Rack / station status information",
        [0x94] = "Rack / station status information",
        [0x95] = "Extended DP master system information",
        [0x96] = "Module status information, PROFINET IO and PROFIBUS DP",
        [0xa0] = "Diagnostic buffer of the CPU",
        [0xb1] = "Module diagnostic information (data record 0)" ,
        [0xb2] = "Module diagnostic information (data record 1), geographical address",
        [0xb3] = "Module diagnostic information (data record 1), logical address",
        [0xb4] = "Diagnostic data of a DP slave",
    } &default = function(n: count): string {return "Unknown"; };

    ###############################################################################################
    ####################################  S7comm Block Types   ####################################
    ###############################################################################################
    const s7comm_block_types = {
        ["08"] = "Organization Block",
        ["0A"] = "Data Block",
        ["0B"] = "System Data Block",
        ["0C"] = "Function",
        ["0D"] = "System Function",
        ["0E"] = "Function Block",
        ["0F"] = "System Function Block",
    } &default = function(n: string): string {return "Unknown"; };

    ###############################################################################################
    ##############################  S7comm Destination Filesystem   ###############################
    ###############################################################################################
    const s7comm_destination_filesystem = {
        ["P"] = "Passive",
        ["A"] = "Active",
    } &default = function(n: string): string {return "Unknown"; };

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

    ###############################################################################################
    ################################  S7comm PLC Control Services  ################################
    ###############################################################################################
    const s7comm_plc_control_services = {
        ["_INSE"] =      "Activates a PLC module",
        ["_INS2"] =      "Activates a PLC module",
        ["_DELE"] =      "Removes module from the PLC's passive file system",
        ["P_PROGRAM"] =  "PLC Start / Stop",
        ["_MODU"] =      "PLC Copy Ram to Rom",
        ["_GARB"] =      "Compress PLC memory",
        ["_N_LOGIN_"] =  "Login",
        ["_N_LOGOUT"] =  "Logout",
        ["_N_CANCEL"] =  "Cancels NC alarm",
        ["_N_DASAVE"] =  "PI-Service for copying data from SRAM to FLASH",
        ["_N_DIGIOF"] =  "Turns off digitizing",
        ["_N_DIGION"] =  "Turns on digitizing",
        ["_N_DZERO_"] =  "Set all D numbers invalid for function",
        ["_N_F_OPER"] =  "Opens a file read-only",
        ["_N_OST_OF"] =  "Overstore OFF",
        ["_N_OST_ON"] =  "Overstore ON",
        ["_N_SCALE_"] =  "Unit of measurement setting (metric<->INCH)",
        ["_N_SETUFR"] =  "Activates user frame",
        ["_N_STRTLK"] =  "The global start disable is set",
        ["_N_STRTUL"] =  "The global start disable is reset",
        ["_N_TMRASS"] =  "Resets the Active status",
        ["_N_F_DELE"] =  "Deletes file",
        ["_N_EXTERN"] =  "Selects external program for execution",
        ["_N_EXTMOD"] =  "Selects external program for execution",
        ["_N_F_DELR"] =  "Delete file even without access rights",
        ["_N_F_XFER"] =  "Selects file for uploading",
        ["_N_LOCKE_"] =  "Locks the active file for editing",
        ["_N_SELECT"] =  "Selects program for execution",
        ["_N_SRTEXT"] =  "A file is being marked in _N_EXT_DIR",
        ["_N_F_CLOS"] =  "Closes file",
        ["_N_F_OPEN"] =  "Opens file",
        ["_N_F_SEEK"] =  "Position the file search pointer",
        ["_N_ASUP__"] =  "Assigns interrupt",
        ["_N_CHEKDM"] =  "Start uniqueness check on D numbers",
        ["_N_CHKDNO"] =  "Check whether the tools have unique D numbers",
        ["_N_CONFIG"] =  "Reconfigures machine data",
        ["_N_CRCEDN"] =  "Creates a cutting edge by specifying an edge number",
        ["_N_DELECE"] =  "Deletes a cutting edge",
        ["_N_CREACE"] =  "Creates a cutting edge",
        ["_N_CREATO"] =  "Creates a tool",
        ["_N_DELETO"] =  "Deletes tool",
        ["_N_CRTOCE"] =  "Generate tool with specified edge number",
        ["_N_DELVAR"] =  "Delete data block",
        ["_N_F_COPY"] =  "Copies file within the NCK",
        ["_N_F_DMDA"] =  "Deletes MDA memory",
        ["_N_F_PROT"] =  "Assigns a protection level to a file",
        ["_N_F_RENA"] =  "Renames file",
        ["_N_FINDBL"] =  "Activates search",
        ["_N_IBN_SS"] =  "Sets the set-up switch",
        ["_N_MMCSEM"] =  "MMC-Semaphore",
        ["_N_NCKMOD"] =  "The mode in which the NCK will work is being set",
        ["_N_NEWPWD"] =  "New password",
        ["_N_SEL_BL"] =  "Selects a new block",
        ["_N_SETTST"] =  "Activate tools for replacement tool group",
        ["_N_TMAWCO"] =  "Set the active wear group in one magazine",
        ["_N_TMCRTC"] =  "Create tool with specified edge number",
        ["_N_TMCRTO"] =  "Creates tool in the tool management",
        ["_N_TMFDPL"] =  "Searches an empty place for loading",
        ["_N_TMFPBP"] =  "Searches for empty location",
        ["_N_TMGETT"] =  "Determines T-number for specific toolID with Duplono",
        ["_N_TMMVTL"] =  "Loads or unloads a tool",
        ["_N_TMPCIT"] =  "Sets increment value of the piece counter",
        ["_N_TMPOSM"] =  "Positions a magazine or tool",
        ["_N_TRESMO"] =  "Reset monitoring values",
        ["_N_TSEARC"] =  "Complex search via search screenforms",
    } &default = function(n: string): string {return "unknown";};
}