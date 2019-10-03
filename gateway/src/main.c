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

#include <arpa/inet.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include "gateway.h"
#include "helpers/input-params.h"
#include "fldt-impl-gw.h"
#include "hal/rpi-global-hal.h"
#include "hal/storage/rpi-file-cache.h"

/******************************************************************************/
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    vs_mac_addr_t forced_mac_addr;
    static const vs_fw_manufacture_id_t manufacture_id = GW_MANUFACTURE_ID;
    static const vs_fw_device_type_t device_type = GW_DEVICE_MODEL;
    struct in_addr plc_sim_addr;

    printf("\n\n--------------------------------------------\n");
    printf("Gateway app at %s\n", argv[0]);
    printf("Manufacture ID = \"%s\", Device type = \"%s\"\n", manufacture_id, device_type);
    printf("--------------------------------------------\n\n");

    if (0 != vs_process_commandline_params(argc, argv, &plc_sim_addr, &forced_mac_addr)) {
        return -1;
    }

    if (0 != vs_rpi_start("gateway",
                          plc_sim_addr,
                          forced_mac_addr,
                          &_tl_storage_ctx,
                          &_fw_storage_ctx,
                          manufacture_id,
                          device_type)) {
        return -1;
    }

    VS_LOG_INFO("%s", argv[0]);
    self_path = argv[0];

    // Enable cached file IO
    vs_file_cache_enable(true);

    // Init Thing's FLDT implementation
    CHECK_RET(!vs_sdmp_register_service(vs_sdmp_fldt_server()), -1, "FLDT server is not registered");
    CHECK_RET(!vs_fldt_gateway_init(&forced_mac_addr), -2, "Unable to initialize FLDT");

    // Init gateway object
    init_gateway_ctx(&forced_mac_addr);

    // Start app
    start_gateway_threads();

    // Sleep until CTRL_C
    vs_rpi_hal_sleep_until_stop();

    VS_LOG_INFO("Terminating application ...");

    int res = vs_rpi_hal_update(argc, argv);

    // Clean File cache
    vs_file_cache_clean();

    return res;
}

/******************************************************************************/
