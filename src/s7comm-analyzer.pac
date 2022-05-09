## s7comm-analyzer.pac
##
## Binpac s7comm Analyzer - Adds processing functions to S7COMM_Flow to generate events.
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{

%}

%code{

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
    ###########################  Process data for s7comm_header event  ############################
    ###############################################################################################
    function process_s7comm_header(data: S7comm): bool
        %{
            if ( ::s7comm_header )
            {
                // PDU Reference is little endian so we need to do an endian swap
                uint16 pdu_reference = (${data.pdu_reference} >> 8) | (${data.pdu_reference} << 8);
                zeek::BifEvent::enqueue_s7comm_header(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      ${data.rosctr},
                                                      pdu_reference,
                                                      ${data.parameter_code},
                                                      ${data.error_class},
                                                      ${data.error_code});
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