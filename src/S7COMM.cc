// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#include "S7COMM.h"
#include <zeek/analyzer/protocol/tcp/TCP_Reassembler.h>
#include <zeek/Reporter.h>
#include "events.bif.h"

namespace zeek::analyzer::s7comm {
  S7COMM_TCP_Analyzer::S7COMM_TCP_Analyzer(Connection* c): analyzer::tcp::TCP_ApplicationAnalyzer("S7COMM_TCP", c)
  {
      interp = new binpac::S7COMM::S7COMM_Conn(this);
      had_gap = false;
  }

  S7COMM_TCP_Analyzer::~S7COMM_TCP_Analyzer()
  {
      delete interp;
  }

  void S7COMM_TCP_Analyzer::Done()
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::Done();
      interp->FlowEOF(true);
      interp->FlowEOF(false);
  }

  void S7COMM_TCP_Analyzer::EndpointEOF(bool is_orig)
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
      interp->FlowEOF(is_orig);
  }

  void S7COMM_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
      assert(TCP());
      if(had_gap)
          return;

      try
      {
          interp->NewData(orig, data, data + len);
      }
      catch(const binpac::Exception& e)
      {
          #if ZEEK_VERSION_NUMBER < 40200
          ProtocolViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));

          #else
          AnalyzerViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));

          #endif
      }
  }

  void S7COMM_TCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
  {
      analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
      had_gap = true;
      interp->NewGap(orig, len);
  }
}