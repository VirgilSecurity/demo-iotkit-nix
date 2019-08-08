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

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/secbox/secbox.h>
#include "sdmp_app.h"
#include "gateway.h"
#include "platform/platform_hardware.h"
#include "communication/gateway_netif_plc.h"
#include "secbox_impl/gateway_secbox_impl.h"
#include "event_group_bit_flags.h"
#include "hal/file_io_hal.h"

char self_path[FILENAME_MAX];

char firmware_name[FILENAME_MAX];

static const char *MAC_SHORT = "-m";
static const char *MAC_FULL = "--mac";

static const char *FIRMWARE_SHORT = "-f";
static const char *FIRMWARE_FULL = "--firmware";

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
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    // TODO: Need to use real mac
    vs_mac_addr_t forced_mac_addr;

    VS_IOT_STRCPY(self_path, argv[0]);

    char *mac_str = _get_commandline_arg(argc, argv, MAC_SHORT, MAC_FULL);
    // Check input parameters
    if (!mac_str) {
        printf("usage: \n    virgil-iot-gateway-app %s/%s <forces MAC address>\n    %s/%s <path to new firmware file "
               "(optional) "
               "relative to ~/keystorage/gateway/<mac addr>/sim_fw_images> \n",
               MAC_SHORT,
               MAC_FULL,
               FIRMWARE_SHORT,
               FIRMWARE_FULL);
        return false;
    }

    if (_read_mac_address(mac_str, &forced_mac_addr)) {
        vs_hal_netif_plc_force_mac(forced_mac_addr);
        vs_hal_files_set_mac(forced_mac_addr.bytes);
    } else {
        printf("\nERROR: Error MAC address of simulated device\n\n");
        return -1;
    }

#if SIM_FETCH_FIRMWARE
    char *firmware_str = _get_commandline_arg(argc, argv, FIRMWARE_SHORT, FIRMWARE_FULL);
    if (firmware_str) {
        VS_IOT_STRCPY(firmware_name, firmware_str);
    } else {
        firmware_name[0] = 0;
    }
#endif
    // Init platform specific hardware
    hardware_init();

    // Init PLC interface
    if (0 != vs_sdmp_init(vs_hal_netif_plc())) {
        return -1;
    }

    // Init gateway object
    gtwy_t *gtwy = init_gateway_ctx(&forced_mac_addr);

    vs_logger_init(VS_LOGLEV_DEBUG);
    VS_LOG_DEBUG(self_path);

    // Prepare secbox
    vs_secbox_configure_hal(vs_secbox_gateway());

    // Start SDMP protocol over PLC interface
    // TODO: Need to use freertos interface
    // vs_sdmp_comm_start_thread(plc_netif);
    xEventGroupSetBits(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT);


    // Start app
    start_gateway_threads();
    return 0;
}

/******************************************************************************/
