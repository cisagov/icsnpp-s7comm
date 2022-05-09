// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
#pragma once

#include <zeek/plugin/Plugin.h>
#include "S7COMM.h"

namespace plugin
{
    namespace ICSNPP_S7COMM
    {
        class Plugin : public zeek::plugin::Plugin
        {
            protected:
                virtual zeek::plugin::Configuration Configure();
        };

        extern Plugin plugin;
    }
}
