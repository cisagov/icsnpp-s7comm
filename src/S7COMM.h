// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#pragma once

#include <zeek/analyzer/protocol/tcp/TCP.h>

#include "s7comm_pac.h"

namespace zeek::analyzer::s7comm {
  class S7COMM_TCP_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer
  {
      public:
          S7COMM_TCP_Analyzer(Connection* conn);
          virtual ~S7COMM_TCP_Analyzer();

          virtual void Done();
          virtual void DeliverStream(int len, const u_char* data, bool orig);
          virtual void Undelivered(uint64_t seq, int len, bool orig);

          virtual void EndpointEOF(bool is_orig);

          static analyzer::Analyzer* Instantiate(Connection* conn)
          {
              return new S7COMM_TCP_Analyzer(conn);
          }

      protected:
          binpac::S7COMM::S7COMM_Conn* interp;
          bool had_gap;
  };
}
