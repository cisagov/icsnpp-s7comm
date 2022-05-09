## consts.pac
##
## Binpac s7comm Analyzer - Contains the constants definitions for s7comm, s7comm-plus, and COTP
##
## Author:   Stephen Kleinheider
## Contact:  stephen.kleinheider@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

############################################################
################  S7comm & S7comm Plus ID  #################
############################################################
enum s7comm_id
{
    S7COMM_ID = 0x32,
    S7COMM_PLUS_ID = 0x72,
}

############################################################
####################  COTP PDU Types  ######################
############################################################
enum cotp_pdu_types
{
    EXPEDITED_DATA = 0x1,
    EXPEDITED_DATA_ACKNOWLEDGEMENT = 0x2,
    REJECT = 0x5,
    DATA_ACKNOWLEDGEMENT = 0x6,
    TPDU_ERROR = 0x7,
    DISCONNECT_REQUEST = 0x8,
    DISCONNECT_CONFIRM = 0xc,
    CONNECTION_CONFIRM = 0xd,
    CONNECTION_REQUEST = 0xe,
    DATA = 0xf,
}

############################################################
####  S7comm Remote Operating Service Control (ROSCTR)  ####
############################################################
enum s7comm_rosctr
{
    JOB = 0x01,
    ACK = 0x02,
    ACK_DATA = 0x03,
    USER_DATA = 0x07,
}

############################################################
###############  S7comm Parameter Functions  ###############
############################################################
enum s7comm_function_codes
{
    CPU_SERVICES = 0x00,
    READ_VARIABLE = 0x04,
    WRITE_VARIABLE = 0x05,
    REQUEST_DOWNLOAD = 0x1a,
    DOWNLOAD_BLOCK = 0x1b,
    DOWNLOAD_ENDED = 0x1c,
    START_UPLOAD = 0x1d,
    UPLOAD = 0x1e,
    END_UPLOAD = 0x1f,
    PLC_CONTROL = 0x28,
    PLC_STOP = 0x29,
    SETUP_COMMUNICATION = 0xf0,
}

############################################################
##################  S7comm-plus Opcodes  ###################
############################################################
enum s7comm_plus_opcodes
{
    REQUEST = 0x31,
    RESPONSE = 0x32,
    NOTIFICATION = 0x33,
}