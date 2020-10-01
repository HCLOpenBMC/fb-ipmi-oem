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

#include <fcntl.h>
#include <ipmid/api.h>
#include <sys/stat.h>
#include <unistd.h>

#include <appcommands.hpp>
#include <commandutils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <ipmid/api.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));
static constexpr size_t GUID_SIZE = 16;
// TODO Make offset and location runtime configurable to ensure we
// can make each define their own locations.
static constexpr off_t OFFSET_SYS_GUID = 0x17F0;
static constexpr const char* FRU_EEPROM = "/sys/bus/i2c/devices/6-0054/eeprom";

// TODO: Need to store this info after identifying proper storage
static uint8_t globEna = 0x09;
static SysInfoParam sysInfoParams;
nlohmann::json appData __attribute__((init_priority(101)));

using IpmbMethodType =
    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;

void printGUID(uint8_t* guid, off_t offset)
{
    std::cout << "Read GUID from offset : " << offset << " :\n";
    for (int i = 0; i < GUID_SIZE; i++)
    {
        int data = guid[i];
        std::cout << std::hex << data << " ";
    }
    std::cout << std::endl;
}

int getGUID(off_t offset, uint8_t* guid)
{
    int fd = -1;
    ssize_t bytes_rd;
    int ret = 0;

    errno = 0;

    // Check if file is present
    if (access(FRU_EEPROM, F_OK) == -1)
    {
        std::cerr << "Unable to access: " << FRU_EEPROM << std::endl;
        return errno;
    }

    // Open the file
    fd = open(FRU_EEPROM, O_RDONLY);
    if (fd == -1)
    {
        std::cerr << "Unable to open: " << FRU_EEPROM << std::endl;
        return errno;
    }

    // seek to the offset
    lseek(fd, offset, SEEK_SET);

    // Read bytes from location
    bytes_rd = read(fd, guid, GUID_SIZE);
    if (bytes_rd != GUID_SIZE)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GUID read data from EEPROM failed");
        ret = errno;
    }
    else
    {
        printGUID(guid, offset);
    }
    close(fd);
    return ret;
}

int getSystemGUID(uint8_t* guid)
{
    return getGUID(OFFSET_SYS_GUID, guid);
}

//----------------------------------------------------------------------
// Get Self Test Results (IPMI/Section 20.4) (CMD_APP_GET_SELFTEST_RESULTS)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetSTResults(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

    // TODO: Following data needs to be updated based on self-test results
    *res++ = 0x55; // Self-Test result
    *res++ = 0x00; // Extra error info in case of failure

    *data_len = 2;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Manufacturing Test On (IPMI/Section 20.5) (CMD_APP_MFR_TEST_ON)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppMfrTestOn(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    std::string mfrTest = "sled-cycle";

    if (!memcmp(req, mfrTest.data(), mfrTest.length()) &&
        (*data_len == mfrTest.length()))
    {
        /* sled-cycle the BMC */
        system("/usr/sbin/power-util sled-cycle");
    }
    else
    {
        return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
    }

    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set Global Enables (CMD_APP_SET_GLOBAL_ENABLES)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppSetGlobalEnables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);

    globEna = *req;
    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Global Enables (CMD_APP_GET_GLOBAL_ENABLES)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetGlobalEnables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

    *data_len = 1;
    *res++ = globEna;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Clear Message flags (IPMI/Section 22.3) (CMD_APP_CLEAR_MESSAGE_FLAGS)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppClearMsgFlags(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    // Do Nothing and just return success
    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get System GUID (CMD_APP_GET_SYS_GUID)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetSysGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    if (getSystemGUID(res))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = GUID_SIZE;
    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Platform specific functions for storing app data
//----------------------------------------------------------------------

void flush_app_data()
{
    std::ofstream file(JSON_APP_DATA_FILE);
    file << appData;
    file.close();
    return;
}

static int platSetSysFWVer(uint8_t* ver)
{
    std::stringstream ss;
    int i;

    /* TODO: implement byte 1: Set selector
     * byte 2: encodeing, currently only supported
     * ASCII which is value 0, UTF and unicode are
     * not supported yet.
     */
    if (ver[1] & 0x0f)
        return -1;

    for (i = 3; i < 3 + ver[2]; i++)
    {
        ss << (char)ver[i];
    }

    appData[KEY_SYSFW_VER] = ss.str();
    flush_app_data();

    return 0;
}

static int platGetSysFWVer(uint8_t* ver)
{
    std::string str = appData[KEY_SYSFW_VER].get<std::string>();
    int len;

    *ver++ = 0; // byte 1: Set selector not supported
    *ver++ = 0; // byte 2: Only ASCII supported

    len = str.length();
    *ver++ = len;
    memcpy(ver, str.data(), len);
    printf("Len : %d ver : %d \n",len,*ver);

    return (len + 3);
}

static std::vector<uint8_t> oem(uint8_t* res)
{
    std::cerr << "OEM" << "\n";
    printf("%d \n",*res);
    std::cout.flush();

//    *res++ = 0; // byte 1: Set selector not supported
//    *res++ = 0; // byte 2: Only ASCII supported

    uint8_t netFn = 0x38;
    uint8_t cmd = 0x0b;
    uint8_t lun = 0;
    uint8_t host = 0;
    std::vector<uint8_t> me{0x15, 0xa0, 0, 3};
    std::vector<uint8_t> cpld{0x15, 0xa0, 0, 1};
    std::vector<uint8_t> bridgeIC{0x15, 0xa0, 0, 2};


    auto bus = getSdBus();
//    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

    auto method = bus->new_method_call("xyz.openbmc_project.Ipmi.Channel.Ipmb",
                                       "/xyz/openbmc_project/Ipmi/Channel/Ipmb",
                                       "org.openbmc.Ipmb", "sendRequest");

    std::cerr << "ME version" << "\n";

    method.append(host, netFn, lun, cmd, me);

    auto reply = bus->call(method);
    if (reply.is_method_error())
    {
        std::cerr << "Error reading from ME\n";
//        return -1;
    }

    IpmbMethodType resp;
    reply.read(resp);

/*    uint8_t a = std::get<0>(resp);
    uint8_t b = std::get<1>(resp);
    uint8_t c = std::get<2>(resp);
    uint8_t d = std::get<3>(resp);
    uint8_t e = std::get<4>(resp);

    printf("\n Response : %d : %d : %d : %d : %d \n",a,b,c,d,e);
    std::cout.flush();
*/
    std::vector<uint8_t> data;
    data = std::get<5>(resp);

    for(int i=0; i<data.size(); i++)
    {
       printf(" : %d ", data.at(i));
       std::cout.flush();
    }

    int len = data.size();
//    *res++ = len;
    memcpy(res, data.data(), len);
    std::cerr << "\n OEM Versions \n ";
    return data;

//  CPLD

/*    std::cerr << "\n CPLD version" << "\n";

    auto method1 = bus->new_method_call("xyz.openbmc_project.Ipmi.Channel.Ipmb",
                                       "/xyz/openbmc_project/Ipmi/Channel/Ipmb",
                                       "org.openbmc.Ipmb", "sendRequest");
    method1.append(host, netFn, lun, cmd, cpld);

    auto reply1 = bus->call(method1);
    if (reply1.is_method_error())
    {
        std::cerr << "Error reading from CPLD\n";
//        return -1;
    }

    IpmbMethodType resp1;
    reply1.read(resp1);

    uint8_t data1 = std::get<0>(resp1);
    uint8_t data2 = std::get<1>(resp1);
    uint8_t data3 = std::get<2>(resp1);
    uint8_t data4 = std::get<3>(resp1);
    uint8_t data5 = std::get<4>(resp1);

    printf("Response : %d : %d : %d : %d : %d \n",data1,data2,data3,data4,data5);
    std::cout.flush();

    std::vector<uint8_t> data0;
    data0 = std::get<5>(resp1);

    for(int i=0; i<data0.size(); i++)
    {
       printf(" : %d ", data0.at(i));
       std::cout.flush();
    }

//  BridgeIC

    std::cerr << "\n Bridge IC Version" << "\n";

    auto method2 = bus->new_method_call("xyz.openbmc_project.Ipmi.Channel.Ipmb",
                                       "/xyz/openbmc_project/Ipmi/Channel/Ipmb",
                                       "org.openbmc.Ipmb", "sendRequest");
    method2.append(host, netFn, lun, cmd, bridgeIC);

    auto reply2 = bus->call(method2);
    if (reply2.is_method_error())
    {
        std::cerr << "Error reading from Bridge IC \n";
//        return -1;
    }

    IpmbMethodType resp2;
    reply2.read(resp2);

    uint8_t d1 = std::get<0>(resp2);
    uint8_t d2 = std::get<1>(resp2);
    uint8_t d3 = std::get<2>(resp2);
    uint8_t d4 = std::get<3>(resp2);
    uint8_t d5 = std::get<4>(resp2);

    printf("Response : %d : %d : %d : %d : %d \n",d1,d2,d3,d4,d5);
    std::cout.flush();

    std::vector<uint8_t> d0;
    d0 = std::get<5>(resp2);

    std::cerr << "\n Version \n";

    for(int i=0; i<d0.size(); i++)
    {
       printf(" : %d ", d0.at(i));
       std::cout.flush();
    }
    
    std::cerr << "\n Firmware Version \n";

    return d0;
*/
}

//----------------------------------------------------------------------
// Set Sys Info Params (IPMI/Sec 22.14a) (CMD_APP_SET_SYS_INFO_PARAMS)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppSetSysInfoParams(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);

    uint8_t param = req[0];
    uint8_t req_len = *data_len;

    *data_len = 0;

    switch (param)
    {
        case SYS_INFO_PARAM_SET_IN_PROG:
            sysInfoParams.set_in_prog = req[1];
            break;
        case SYS_INFO_PARAM_SYSFW_VER:
            memcpy(sysInfoParams.sysfw_ver, &req[1], SIZE_SYSFW_VER);
            if (platSetSysFWVer(sysInfoParams.sysfw_ver))
                return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
            break;
        case SYS_INFO_PARAM_SYS_NAME:
            memcpy(sysInfoParams.sys_name, &req[1], SIZE_SYS_NAME);
            break;
        case SYS_INFO_PARAM_PRI_OS_NAME:
            memcpy(sysInfoParams.pri_os_name, &req[1], SIZE_OS_NAME);
            break;
        case SYS_INFO_PARAM_PRESENT_OS_NAME:
            memcpy(sysInfoParams.present_os_name, &req[1], SIZE_OS_NAME);
            break;
        case SYS_INFO_PARAM_PRESENT_OS_VER:
            memcpy(sysInfoParams.present_os_ver, &req[1], SIZE_OS_VER);
            break;
        case SYS_INFO_PARAM_BMC_URL:
            memcpy(sysInfoParams.bmc_url, &req[1], SIZE_BMC_URL);
            break;
        case SYS_INFO_PARAM_OS_HV_URL:
            memcpy(sysInfoParams.os_hv_url, &req[1], SIZE_OS_HV_URL);
            break;
        case SYS_INFO_PARAM_BIOS_CURRENT_BOOT_LIST:
            memcpy(sysInfoParams.bios_current_boot_list, &req[1], req_len);
            appData[KEY_BIOS_BOOT_LEN] = req_len;
            flush_app_data();
            break;
        case SYS_INFO_PARAM_BIOS_FIXED_BOOT_DEVICE:
            if (SIZE_BIOS_FIXED_BOOT_DEVICE != req_len)
                break;
            memcpy(sysInfoParams.bios_fixed_boot_device, &req[1],
                   SIZE_BIOS_FIXED_BOOT_DEVICE);
            break;
        case SYS_INFO_PARAM_BIOS_RSTR_DFLT_SETTING:
            if (SIZE_BIOS_RSTR_DFLT_SETTING != req_len)
                break;
            memcpy(sysInfoParams.bios_rstr_dflt_setting, &req[1],
                   SIZE_BIOS_RSTR_DFLT_SETTING);
            break;
        case SYS_INFO_PARAM_LAST_BOOT_TIME:
            if (SIZE_LAST_BOOT_TIME != req_len)
                break;
            memcpy(sysInfoParams.last_boot_time, &req[1], SIZE_LAST_BOOT_TIME);
            break;
        default:
            return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
            break;
    }

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Sys Info Params (IPMI/Sec 22.14b) (CMD_APP_GET_SYS_INFO_PARAMS)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetSysInfoParams(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

    uint8_t param = req[1];
    uint8_t len;
    std::vector<uint8_t> v;
    *res++ = 1; // Parameter revision
    *data_len = 1;

    switch (param)
    {
        case SYS_INFO_PARAM_OEM:
            std::cerr << "\n SYS_INFO_PARAM_OEM" << "\n";
            v = oem(res);
//            *res++ = v;
            *data_len += SIZE_OEM;
        case SYS_INFO_PARAM_SET_IN_PROG:
            *res++ = sysInfoParams.set_in_prog;
            *data_len += 1;
            break;
        case SYS_INFO_PARAM_SYSFW_VER:
            if ((len = platGetSysFWVer(res)) < 0)
                return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
            *data_len += SIZE_SYSFW_VER;
            break;
        case SYS_INFO_PARAM_SYS_NAME:
            memcpy(res, sysInfoParams.sys_name, SIZE_SYS_NAME);
            *data_len += SIZE_SYS_NAME;
            break;
        case SYS_INFO_PARAM_PRI_OS_NAME:
            memcpy(res, sysInfoParams.pri_os_name, SIZE_OS_NAME);
            *data_len += SIZE_OS_NAME;
            break;
        case SYS_INFO_PARAM_PRESENT_OS_NAME:
            memcpy(res, sysInfoParams.present_os_name, SIZE_OS_NAME);
            *data_len += SIZE_OS_NAME;
            break;
        case SYS_INFO_PARAM_PRESENT_OS_VER:
            memcpy(res, sysInfoParams.present_os_ver, SIZE_OS_VER);
            *data_len += SIZE_OS_VER;
            break;
        case SYS_INFO_PARAM_BMC_URL:
            memcpy(res, sysInfoParams.bmc_url, SIZE_BMC_URL);
            *data_len += SIZE_BMC_URL;
            break;
        case SYS_INFO_PARAM_OS_HV_URL:
            memcpy(res, sysInfoParams.os_hv_url, SIZE_OS_HV_URL);
            *data_len += SIZE_OS_HV_URL;
            break;
        case SYS_INFO_PARAM_BIOS_CURRENT_BOOT_LIST:
            len = appData[KEY_BIOS_BOOT_LEN].get<uint8_t>();
            memcpy(res, sysInfoParams.bios_current_boot_list, len);
            *data_len += len;
            break;
        case SYS_INFO_PARAM_BIOS_FIXED_BOOT_DEVICE:
            memcpy(res, sysInfoParams.bios_fixed_boot_device,
                   SIZE_BIOS_FIXED_BOOT_DEVICE);
            *data_len += SIZE_BIOS_FIXED_BOOT_DEVICE;
            break;
        case SYS_INFO_PARAM_BIOS_RSTR_DFLT_SETTING:
            memcpy(res, sysInfoParams.bios_rstr_dflt_setting,
                   SIZE_BIOS_RSTR_DFLT_SETTING);
            *data_len += SIZE_BIOS_RSTR_DFLT_SETTING;
            break;
        case SYS_INFO_PARAM_LAST_BOOT_TIME:
            memcpy(res, sysInfoParams.last_boot_time, SIZE_LAST_BOOT_TIME);
            *data_len += SIZE_LAST_BOOT_TIME;
            break;
        default:
            return IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
            break;
    }
    return IPMI_CC_OK;
}

void registerAPPFunctions()
{
    /* Get App data stored in json file */
    std::ifstream file(JSON_APP_DATA_FILE);
    if (file)
    {
        file >> appData;
        file.close();
    }

    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_SELFTEST_RESULTS, NULL,
                         ipmiAppGetSTResults,
                         PRIVILEGE_USER); // Get Self Test Results
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_MFR_TEST_ON, NULL,
                         ipmiAppMfrTestOn,
                         PRIVILEGE_USER); // Manufacturing Test On
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_SET_GLOBAL_ENABLES, NULL,
                         ipmiAppSetGlobalEnables,
                         PRIVILEGE_USER); // Set Global Enables
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_GLOBAL_ENABLES, NULL,
                         ipmiAppGetGlobalEnables,
                         PRIVILEGE_USER); // Get Global Enables
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_CLEAR_MESSAGE_FLAGS, NULL,
                         ipmiAppClearMsgFlags,
                         PRIVILEGE_USER); // Clear Message flags
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_SYS_GUID, NULL,
                         ipmiAppGetSysGUID,
                         PRIVILEGE_USER); // Get System GUID
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_SET_SYS_INFO_PARAMS, NULL,
                         ipmiAppSetSysInfoParams,
                         PRIVILEGE_USER); // Set Sys Info Params
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_SYS_INFO_PARAMS, NULL,
                         ipmiAppGetSysInfoParams,
                         PRIVILEGE_USER); // Get Sys Info Params
    return;
}

} // namespace ipmi
