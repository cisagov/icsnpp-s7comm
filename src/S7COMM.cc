// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#include "S7COMM.h"
#include <zeek/analyzer/protocol/tcp/TCP_Reassembler.h>
#include <zeek/Reporter.h>
#include "events.bif.h"

namespace {
  // RFC 1006 TPKT header: version 3, reserved 0, 16-bit big-endian length that
  // covers the header itself. The smallest legal S7/COTP packet is TPKT(4) +
  // COTP DT header(3) = 7 bytes; an S7 PDU never approaches the 16-bit ceiling,
  // so cap the plausibility window at the largest negotiated PDU size plus
  // headers. Used only to re-find a frame boundary after a gap.
  inline bool looks_like_tpkt(int len, const u_char* data)
  {
      if ( len < 7 || data[0] != 0x03 || data[1] != 0x00 )
          return false;
      const int tpkt_len = (static_cast<int>(data[2]) << 8) | static_cast<int>(data[3]);
      return tpkt_len >= 7 && tpkt_len <= 8192;
  }
}

namespace zeek::analyzer::s7comm {
  S7COMM_TCP_Analyzer::S7COMM_TCP_Analyzer(Connection* c): analyzer::tcp::TCP_ApplicationAnalyzer("S7COMM_TCP", c)
  {
      interp = new binpac::S7COMM::S7COMM_Conn(this);
      resync_orig = false;
      resync_resp = false;
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

      bool& resync = orig ? resync_orig : resync_resp;

      if ( resync )
      {
          // The flow buffer was reset by NewGap(). Zeek resumes delivery at the
          // first byte after the hole, which is only a PDU boundary by luck, so
          // discard chunks until one starts with a plausible TPKT header. This
          // costs at most the remainder of the PDU the gap fell inside; it never
          // silences the rest of the connection the way the old connection-wide latch did.
          if ( ! looks_like_tpkt(len, data) )
              return;

          resync = false;
      }

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
      // Tell binpac to drop whatever partial frame it had buffered for THIS
      // direction, then wait for the next TPKT boundary in that direction only.
      // The peer direction keeps parsing.
      (orig ? resync_orig : resync_resp) = true;
      interp->NewGap(orig, len);
  }
}
