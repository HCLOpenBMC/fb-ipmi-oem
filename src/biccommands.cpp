/*
 * Copyright (c)  2018 Intel Corporation.
 * Copyright (c)  2018-present Facebook.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "xyz/openbmc_project/Common/error.hpp"
#include <ipmid/api.h>
//#include <ipmid/api.hpp>

#include <nlohmann/json.hpp>
#include <array>
#include <commandutils.hpp>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <biccommands.hpp>
//#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>

#include <boost/algorithm/string/replace.hpp>
#include <ipmid/handler.hpp>

#include <sys/types.h>
#include <unistd.h>

#include <ipmid/api.hpp>
namespace ipmi
{

using namespace phosphor::logging;

static void registerBICFunctions() __attribute__((constructor));

//sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h

constexpr uint8_t ipmbAddressTo7BitSet(uint8_t address)
{
    return address >> 1;
}

extern message::Response::ptr executeIpmiCommand(message::Request::ptr request);

// Added for debug
ipmi_ret_t ipmiOemBicHandler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
        phosphor::logging::log<phosphor::logging::level::ERR>(
          "[FBOEM][IPMI BIC HANDLER] Called 1\n");

	ipmi_bic_req_t *bic_req = reinterpret_cast<ipmi_bic_req_t *>(request);

	printf(" header : %x\t%x\t%x\t%x \n", bic_req->data[0], bic_req->data[1], bic_req->data[2], bic_req->data[3]);
	printf(" netfn : %x\n", bic_req->ipmi_req.netfn);
	printf(" cmd : %x\n", bic_req->ipmi_req.cmd);

	std::cout.flush();

       Privilege privilege = Privilege::Admin;
       int rqSA = 0;
       uint8_t userId = 0; // undefined user
       uint32_t sessionId = 0;
       uint32_t channel= 0;
       boost::asio::yield_context yield;
       std::vector<uint8_t> data;

        auto ctx =
        std::make_shared<ipmi::Context>(getSdBus(), bic_req->ipmi_req.netfn, bic_req->ipmi_req.cmd, channel, userId,
                                        sessionId, privilege, rqSA, yield);
    auto req = std::make_shared<ipmi::message::Request>(
        ctx, std::forward<std::vector<uint8_t>>(data));
     message::Response::ptr resp = executeIpmiCommand(req); 

        phosphor::logging::log<phosphor::logging::level::ERR>(
          "[FBOEM][IPMI BIC HANDLER] Called 2\n");
      
        return IPMI_CC_OK;
}

static void registerBICFunctions(void)
{

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering BIC commands");

    ipmiPrintAndRegister(NETFUN_FB_OEM_BIC, CMD_OEM_BIC_INFO, NULL,
                          ipmiOemBicHandler,
                         PRIVILEGE_USER); // Yv2 Bic Info
    return;
} 

} // namespace ipmi
