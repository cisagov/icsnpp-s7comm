## s7comm-analyzer.pac
##
## Binpac s7comm Analyzer - Adds processing functions to S7COMM_Flow to generate events.
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    string get_string(const_bytestring data);
%}

%code{
    string get_string(const_bytestring data){
        string str = "";

        for ( int32 i = 0; i < data.length(); ++i )
            str += data[i];

        return str;
    }
%}

refine flow S7COMM_Flow += {

    ###############################################################################################
    ################################  Process data for cotp event  ################################
    ###############################################################################################
    function process_cotp(data: COTP): bool
        %{
            if ( ::cotp )
            {
                zeek::BifEvent::enqueue_cotp(connection()->zeek_analyzer(),
                                             connection()->zeek_analyzer()->Conn(),
                                             ${data.pdu_type});
            }
            return true;
        %}

    ###############################################################################################
    ##################### Process data for rosctr_job -> s7comm_header event  #####################
    ###############################################################################################
    function process_rosctr_job(data: ROSCTR_Job): bool
        %{
            if ( ::s7comm_header )
            {
                // Event for PLC Control function in produced a function process_rosctr_job_plc_control so do not process function code 0x28 here
                if ( ${data.function_code} != 0x28 )
                {
                    // PDU Reference is little endian so we need to do an endian swap
                    uint16 pdu_reference = (${data.pdu_reference} >> 8) | (${data.pdu_reference} << 8);
                    zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        JOB,
                                                        pdu_reference,
                                                        ${data.function_code},
                                                        0xff,
                                                        zeek::make_intrusive<zeek::StringVal>(""),
                                                        0xff,
                                                        0xff);
                }
            }
            return true;
        %}

    ###############################################################################################
    ############### Process data for rosctr_job_plc_control -> s7comm_header event  ###############
    ###############################################################################################
    function process_rosctr_job_plc_control(data: ROSCTR_Job_PLC_Control): bool
        %{
            if ( ::s7comm_header )
            {
                // PDU Reference is little endian so we need to do an endian swap
                uint16 pdu_reference = (${data.pdu_reference} >> 8) | (${data.pdu_reference} << 8);
                zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      JOB,
                                                      pdu_reference,
                                                      0x28,
                                                      0xff,
                                                      zeek::make_intrusive<zeek::StringVal>(get_string(${data.plc_control_name})),
                                                      0xff,
                                                      0xff);
            }
            return true;
        %}

    ###############################################################################################
    ##################### Process data for rosctr_ack -> s7comm_header event  #####################
    ###############################################################################################
    function process_rosctr_ack(data: ROSCTR_ACK): bool
        %{
            if ( ::s7comm_header )
            {
                // PDU Reference is little endian so we need to do an endian swap
                uint16 pdu_reference = (${data.pdu_reference} >> 8) | (${data.pdu_reference} << 8);
                zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      ACK,
                                                      pdu_reference,
                                                      ${data.function_code},
                                                      0xff,
                                                      zeek::make_intrusive<zeek::StringVal>(""),
                                                      ${data.error_class},
                                                      ${data.error_code});
            }
            return true;
        %}

    ###############################################################################################
    ################## Process data for rosctr_ack_data -> s7comm_header event  ###################
    ###############################################################################################
    function process_rosctr_ack_data(data: ROSCTR_ACK_Data): bool
        %{
            if ( ::s7comm_header )
            {
                // PDU Reference is little endian so we need to do an endian swap
                uint16 pdu_reference = (${data.pdu_reference} >> 8) | (${data.pdu_reference} << 8);
                zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      ACK_DATA,
                                                      pdu_reference,
                                                      ${data.function_code},
                                                      0xff,
                                                      zeek::make_intrusive<zeek::StringVal>(""),
                                                      ${data.error_class},
                                                      ${data.error_code});
            }
            return true;
        %}

    ###############################################################################################
    ############## Process data for rosctr_user_data_request -> s7comm_header event  ##############
    ###############################################################################################
    function process_rosctr_user_data_request(data: ROSCTR_User_Data_Request): bool
        %{
            if ( ::s7comm_header )
            {
                // PDU Reference is little endian so we need to do an endian swap
                uint16 pdu_reference = (${data.user_data.pdu_reference} >> 8) | (${data.user_data.pdu_reference} << 8);
                zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      USER_DATA,
                                                      pdu_reference,
                                                      ${data.user_data.function_code},
                                                      ${data.user_data.subfunction},
                                                      zeek::make_intrusive<zeek::StringVal>(""),
                                                      0xfe,
                                                      0xffff);
            }
            return true;
        %}

    ###############################################################################################
    ############## Process data for rosctr_user_data_response -> s7comm_header event  #############
    ###############################################################################################
    function process_rosctr_user_data_response(data: ROSCTR_User_Data_Response): bool
        %{
            if ( ::s7comm_header )
            {
                // PDU Reference is little endian so we need to do an endian swap
                uint16 pdu_reference = (${data.user_data.pdu_reference} >> 8) | (${data.user_data.pdu_reference} << 8);
                zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      USER_DATA,
                                                      pdu_reference,
                                                      ${data.user_data.function_code},
                                                      ${data.user_data.subfunction},
                                                      zeek::make_intrusive<zeek::StringVal>(""),
                                                      0xfe,
                                                      ${data.error_code});
            }
            return true;
        %}

    ###############################################################################################
    ################## Process data for s7comm_read_szl -> s7comm_read_szl event  #################
    ###############################################################################################
    function process_s7comm_read_szl(data: Read_SZL): bool
        %{
            if ( ::s7comm_read_szl )
            {
                // Fragmented Packets do not contain information we need to log, so ignore those
                if ( ${data.data_reference_id} == 0 or ${data.last_data_unit} == 1)
                {
                    // PDU Reference is little endian so we need to do an endian swap
                    uint16 pdu_reference = (${data.user_data.pdu_reference} >> 8) | (${data.user_data.pdu_reference} << 8);
                    zeek::BifEvent::enqueue_s7comm_read_szl(connection()->zeek_analyzer(),
                                                            connection()->zeek_analyzer()->Conn(),
                                                            pdu_reference,
                                                            ${data.user_data.method},
                                                            ${data.return_code},
                                                            ${data.szl_id},
                                                            ${data.szl_index});
                }
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for s7comm_plus_header event  #########################
    ###############################################################################################
    function process_s7comm_plus_header(data: S7comm_Plus): bool
        %{
            if ( ::s7comm_plus_header )
            {
                uint16 function_code = UINT16_MAX;

                if ( ${data.opcode} == REQUEST || ${data.opcode} == RESPONSE )
                    function_code = ${data.opcode_data} & 0xffff;

                zeek::BifEvent::enqueue_s7comm_plus_header(connection()->zeek_analyzer(),
                                                           connection()->zeek_analyzer()->Conn(),
                                                           ${data.version},
                                                           ${data.opcode},
                                                           function_code);
            }
            return true;
        %}

    ###############################################################################################
    ################################  Process data for tpkt event  ################################
    ###############################################################################################
    function process_tpkt(data: TPKT): bool
        %{
            if ( ::tpkt )
            {
                zeek::BifEvent::enqueue_tpkt(connection()->zeek_analyzer(),
                                             connection()->zeek_analyzer()->Conn(),
                                             ${data.version},
                                             ${data.reserved},
                                             ${data.length});
            }
            return true;
        %}

    ###############################################################################################
    #############################  Process data for cotp_data event  ##############################
    ###############################################################################################
    function process_cotp_data(data: COTP_Data): bool
        %{
            if ( ::cotp_data )
            {
                zeek::BifEvent::enqueue_cotp_data(connection()->zeek_analyzer(),
                                                  connection()->zeek_analyzer()->Conn(),
                                                  ${data.tpdu_sequence_num},
                                                  ${data.eot},
                                                  to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for cotp_cotp_connection_request event  ####################
    ###############################################################################################
    function process_cotp_connection_request(data: COTP_Connection_Request): bool
        %{
            if ( ::cotp_connection_request )
            {
                zeek::BifEvent::enqueue_cotp_connection_request(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                ${data.dst_reference},
                                                                ${data.src_reference},
                                                                ${data.class_id},
                                                                ${data.extended_format},
                                                                ${data.explicit_flow_control},
                                                                to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for cotp_connection_confirm event  #######################
    ###############################################################################################
    function process_cotp_connection_confirm(data: COTP_Connection_Confirm): bool
        %{
            if ( ::cotp_connection_confirm )
            {
                zeek::BifEvent::enqueue_cotp_connection_confirm(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                ${data.dst_reference},
                                                                ${data.src_reference},
                                                                ${data.class_id},
                                                                ${data.extended_format},
                                                                ${data.explicit_flow_control},
                                                                to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for cotp_disconnect_request event  #######################
    ###############################################################################################
    function process_cotp_disconnect_request(data: COTP_Disconnect_Request): bool
        %{
            if ( ::cotp_disconnect_request )
            {
                zeek::BifEvent::enqueue_cotp_disconnect_request(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                ${data.dst_reference},
                                                                ${data.src_reference},
                                                                ${data.reason},
                                                                to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for cotp_disconnect_confirm event  #######################
    ###############################################################################################
    function process_cotp_disconnect_confirm(data: COTP_Disconnect_Confirm): bool
        %{
            if ( ::cotp_disconnect_confirm )
            {
                zeek::BifEvent::enqueue_cotp_disconnect_confirm(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                ${data.dst_reference},
                                                                ${data.src_reference},
                                                                to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for cotp_expedited_data event  ########################
    ###############################################################################################
    function process_cotp_expedited_data(data: COTP_Expedited_Data): bool
        %{
            if ( ::cotp_expedited_data )
            {
                zeek::BifEvent::enqueue_cotp_expedited_data(connection()->zeek_analyzer(),
                                                            connection()->zeek_analyzer()->Conn(),
                                                            ${data.dst_reference},
                                                            ${data.tpdu_id},
                                                            ${data.eot},
                                                            to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for cotp_data_acknowledgement event  ######################
    ###############################################################################################
    function process_cotp_data_acknowledgement(data: COTP_Data_Acknowledgement): bool
        %{
            if ( ::cotp_data_acknowledgement )
            {
                zeek::BifEvent::enqueue_cotp_data_acknowledgement(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 ${data.dst_reference},
                                                                 ${data.next_tpdu},
                                                                 to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for cotp_data_acknowledgement event  #####################
    ###############################################################################################
    function process_cotp_expedited_data_acknowledgement(data: COTP_Expedited_Data_Acknowledgement): bool
        %{
            if ( ::cotp_expedited_data_acknowledgement )
            {
                zeek::BifEvent::enqueue_cotp_expedited_data_acknowledgement(connection()->zeek_analyzer(),
                                                                            connection()->zeek_analyzer()->Conn(),
                                                                            ${data.dst_reference},
                                                                            ${data.tpdu_id},
                                                                            to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cotp_reject event  #############################
    ###############################################################################################
    function process_cotp_reject(data: COTP_Reject): bool
        %{
            if ( ::cotp_reject )
            {
                zeek::BifEvent::enqueue_cotp_reject(connection()->zeek_analyzer(),
                                                    connection()->zeek_analyzer()->Conn(),
                                                    ${data.dst_reference},
                                                    ${data.next_tpdu},
                                                    to_stringval(${data.variable_data}));
            }
            return true;
        %}

    ###############################################################################################
    #############################  Process data for cotp_error event  #############################
    ###############################################################################################
    function process_cotp_error(data: COTP_Error): bool
        %{
            if ( ::cotp_error )
            {
                zeek::BifEvent::enqueue_cotp_error(connection()->zeek_analyzer(),
                                                   connection()->zeek_analyzer()->Conn(),
                                                   ${data.dst_reference},
                                                   ${data.error_code},
                                                   to_stringval(${data.variable_data}));
            }
            return true;
        %}

};