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
#include "platform_hardware.h"
#include "communication/gateway_netif_plc.h"
#include "secbox_impl/gateway_secbox_impl.h"
#include "event_group_bit_flags.h"

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

    if (argc == 2 && _read_mac_address(argv[1], &forced_mac_addr)) {
        vs_hal_netif_plc_force_mac(forced_mac_addr);
    } else {
        printf("\nERROR: need to set MAC address of simulated device\n\n");
        return -1;
    }

    const vs_netif_t *plc_netif = NULL;

    // Init platform specific hardware
    hardware_init();

    // Init gateway object
    gtwy_t *gtwy = init_gateway_ctx(&forced_mac_addr);

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Prepare secbox
    vs_secbox_configure_hal(vs_secbox_gateway());

    // Get PLC Network interface
    plc_netif = vs_hal_netif_plc();

    // Start SDMP protocol over PLC interface
    // TODO: Need to use freertos interface
    // vs_sdmp_comm_start_thread(plc_netif);
    xEventGroupSetBits(gtwy->shared_event_group, SDMP_INIT_FINITE_BIT);


    // Start app
    start_gateway_threads();
    return 0;
}

/******************************************************************************/
