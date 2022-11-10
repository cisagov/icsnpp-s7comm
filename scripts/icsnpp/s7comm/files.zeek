##! main.zeek
##!
##! Binpac S7comm Protocol Analyzer - Contains the file analysis script-layer functionality 
##!                                   for extracting S7comm upload/download files.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

@load base/frameworks/files
@load ./main

module S7COMM;

export {
    ## Default file handle provider for BACNET
    global get_file_handle: function(c: connection, is_orig: bool): string;

    ## Default file describer for BACNET
    global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
    {
        if ( c?$filename ){
            return cat(Analyzer::ANALYZER_S7COMM_TCP, c$id$orig_h, c$id$resp_h, c$filename);
        }
        else
        {
            return cat(Analyzer::ANALYZER_S7COMM_TCP, c$start_time, c$id, is_orig);
        }
    }

function describe_file(f: fa_file): string
    {
        for ( _, c in f$conns )
        {
            if ( c?$filename )
            {
                return c$filename;
            }
        }
        return "s7comm_file";
    }

event zeek_init() &priority=5
    {
        Files::register_protocol(Analyzer::ANALYZER_S7COMM_TCP,
                                 [$get_file_handle = S7COMM::get_file_handle,
                                  $describe        = S7COMM::describe_file]);
    }
