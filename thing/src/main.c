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

#include <unistd.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>

#include "thing.h"
#include "hal/netif/netif-queue.h"
#include "hal/netif/rpi-plc-sim.h"
#include "hal/netif/rpi-udp-broadcast.h"
#include "hal/storage/rpi-file-io.h"
#include "hal/rpi-global-hal.h"
#include "helpers/input-params.h"

/******************************************************************************/
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    vs_mac_addr_t forced_mac_addr;
    struct in_addr plc_sim_addr;
    const vs_netif_t *netif;

    vs_logger_init(VS_LOGLEV_DEBUG);

    VS_LOG_INFO("%s", argv[0]);

    CHECK_RET(vs_process_commandline_params(argc, argv, &plc_sim_addr, &forced_mac_addr),
              -1,
              "Unrecognized command line");

    // Set storage directory
    vs_hal_files_set_dir("thing");

    // Set MAC for emulated device
    vs_hal_files_set_mac(forced_mac_addr.bytes);

    // Prepare TL storage
    vs_tl_init_storage();

    // vs_fldt_init(&forced_mac_addr);

    if (plc_sim_addr.s_addr == htonl(INADDR_ANY)) {
        // Setup UDP Broadcast as network interface
        vs_hal_netif_udp_bcast_force_mac(forced_mac_addr);

        // Get PLC Network interface
        netif = vs_hal_netif_udp_bcast();
    } else {
        // Setup PLC simulator as network interface
        vs_hal_netif_plc_force_mac(forced_mac_addr);

        // Set IP of PLC simulator
        vs_plc_sim_set_ip(plc_sim_addr);

        // Get PLC Network interface
        netif = vs_hal_netif_plc();
    }

    // Initialize SDMP
    CHECK_RET(!vs_sdmp_init(vs_netif_queued(netif)), -1, "Unable to initialize SDMP");
    CHECK_RET(!vs_sdmp_register_service(vs_sdmp_fldt_service()), -3, "Unable to register FLDT service");

    // Init thing object
    //    ???

    // Start app
    //    start_thing_threads();

    // Sleep until CTRL_C
    vs_rpi_hal_sleep_until_stop();

    VS_LOG_INFO("Terminating application ...");

    // vs_fldt_destroy();

    int res = 0; // vs_rpi_hal_update(argc, argv);

    return res;
}

/******************************************************************************/
