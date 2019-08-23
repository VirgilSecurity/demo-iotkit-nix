//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include "sdmp_app.h"
#include "gateway.h"
#include "platform/platform_hardware.h"
#include "communication/gateway_netif_plc.h"
#include "secbox_impl/gateway_secbox_impl.h"
#include "event_group_bit_flags.h"
#include "hal/file_io_hal.h"

char self_path[FILENAME_MAX];

#define CMD_STR_UPDATE_TEMPLATE "mv %s %s; %s %s"

bool is_try_to_update = false;

/******************************************************************************/
static char *
_get_commandline_arg(int argc, char *argv[], const char *shortname, const char *longname) {
    size_t pos;

    if (!(argv && shortname && *shortname && longname && *longname)) {
        return NULL;
    }

    for (pos = 0; pos < argc; ++pos) {
        if (!strcmp(argv[pos], shortname) && (pos + 1) < argc)
            return argv[pos + 1];
        if (!strcmp(argv[pos], longname) && (pos + 1) < argc)
            return argv[pos + 1];
    }

    return NULL;
}

/******************************************************************************/
static bool
_read_mac_address(const char *arg, vs_mac_addr_t *mac) {
    unsigned int values[6];
    int i;

    if (6 ==
        sscanf(arg, "%x:%x:%x:%x:%x:%x%*c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for (i = 0; i < 6; ++i) {
            mac->bytes[i] = (uint8_t)values[i];
        }
        return true;
    }

    return false;
}

/******************************************************************************/
static bool
_process_commandline_params(int argc, char *argv[], struct in_addr *plc_sim_addr, vs_mac_addr_t *forced_mac_addr) {
    static const char *PLC_SIM_ADDRESS_SHORT = "-a";
    static const char *PLC_SIM_ADDRESS_FULL = "--address";
    static const char *MAC_SHORT = "-m";
    static const char *MAC_FULL = "--mac";
    char *mac_str;
    char *plc_sim_addr_str;

    if (!argv || !argc || !plc_sim_addr || !forced_mac_addr) {
        printf("Wrong input parameters.");
        return false;
    }

    mac_str = _get_commandline_arg(argc, argv, MAC_SHORT, MAC_FULL);
    plc_sim_addr_str = _get_commandline_arg(argc, argv, PLC_SIM_ADDRESS_SHORT, PLC_SIM_ADDRESS_FULL);

    // Check input parameters
    if (!mac_str || !plc_sim_addr_str) {
        printf("usage: virgil-iot-gateway-app %s/%s <PLC simulator IP> %s/%s <forces MAC address>\n",
               PLC_SIM_ADDRESS_SHORT,
               PLC_SIM_ADDRESS_FULL,
               MAC_SHORT,
               MAC_FULL);
        return false;
    }

    if (!inet_aton(plc_sim_addr_str, plc_sim_addr)) {
        printf("Incorrect PLC simulator IP address \"%s\" was specified", plc_sim_addr_str);
        return false;
    }

    if (!_read_mac_address(mac_str, forced_mac_addr)) {
        printf("Incorrect forced MAC address \"%s\" was specified", mac_str);
        return false;
    }

    return true;
}

/******************************************************************************/
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    // TODO: Need to use real mac
    vs_mac_addr_t forced_mac_addr;
    struct in_addr plc_sim_addr;


    strncpy(self_path, argv[0], sizeof(self_path));
    vs_logger_init(VS_LOGLEV_DEBUG);
    VS_LOG_DEBUG(self_path);

    CHECK_RET (_process_commandline_params(argc, argv, &plc_sim_addr, &forced_mac_addr), -1, "Unrecognized command line");
    vs_hal_netif_plc_force_mac(forced_mac_addr);
    vs_hal_files_set_mac(forced_mac_addr.bytes);

    // Init platform specific hardware
    hardware_init();

    // Set IP of PLC simulator
    vs_plc_sim_set_ip(plc_sim_addr);

    // Initialize SDMP
    CHECK_RET (!vs_sdmp_comm_start_thread(&forced_mac_addr), -1, "Unable to initialize SDMP interface");

    // Init gateway object
    gtwy_t *gtwy = init_gateway_ctx(&forced_mac_addr);

    // Prepare secbox
    vs_secbox_configure_hal(vs_secbox_gateway());

    // Start SDMP protocol over PLC interface

    // TODO: Need to use freertos interface
    // vs_sdmp_comm_start_thread(plc_netif);
    xEventGroupSetBits(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT);

    // Start app
    start_gateway_threads();

    if (is_try_to_update) {
        char new_app[FILENAME_MAX];
        char cmd_str[FILENAME_MAX];

        size_t pos;

        VS_LOG_INFO("Try to update app");

        VS_IOT_STRCPY(new_app, self_path);

        strcat(new_app, ".new");

        uint32_t args_len = 0;

        for (pos = 1; pos < argc; ++pos) {
            args_len += strlen(argv[pos]);
        }

        char copy_args[args_len + argc + 1];
        copy_args[0] = 0;

        for (pos = 1; pos < argc; ++pos) {
            strcat(copy_args, argv[pos]);
            strcat(copy_args, " ");
        }

        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_UPDATE_TEMPLATE, new_app, self_path, self_path, copy_args);

        VS_LOG_DEBUG(cmd_str);

        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error start new process. errno = %d (%s)", errno, strerror(errno));
        }

        VS_LOG_ERROR("Something wrong");
    }

    VS_LOG_INFO("App stopped");
    return 0;
}

/******************************************************************************/
