// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
#include "Plugin.h"
#include "zeek/analyzer/Component.h"

namespace plugin
{
    namespace ICSNPP_S7COMM
    {
        Plugin plugin;
    }
}

using namespace plugin::ICSNPP_S7COMM;

zeek::plugin::Configuration Plugin::Configure()
{
    AddComponent(new zeek::analyzer::Component("S7COMM_TCP",zeek::analyzer::s7comm::S7COMM_TCP_Analyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "ICSNPP::S7COMM";
    config.description = "S7comm, S7comm-plus, and COTP Protocol analyzer";
    config.version.major = 1;
    config.version.minor = 1;

    return config;
}
