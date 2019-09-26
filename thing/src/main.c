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

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <virgil/iot/trust_list/trust_list.h>

#include "thing.h"
#include "hal/netif/rpi-plc-sim.h"
#include "hal/rpi-global-hal.h"
#include "helpers/input-params.h"
#include "fldt_implementation.h"

#if SIMULATOR
static const char _test_message[] = TEST_UPDATE_MESSAGE;
#endif

/******************************************************************************/
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    vs_mac_addr_t forced_mac_addr;
    struct in_addr plc_sim_addr;
    vs_storage_op_ctx_t *fw_ctx;
    vs_storage_op_ctx_t *tl_ctx;
    int fldt_ret_code;
    static const uint8_t manufacture_id[MANUFACTURE_ID_SIZE] = THING_MANUFACTURE_ID;
    static const uint8_t device_type[DEVICE_TYPE_SIZE] = THING_DEVICE_MODEL;

    if (0 != vs_process_commandline_params(argc, argv, &plc_sim_addr, &forced_mac_addr)) {
        return -1;
    }

    if (0 != vs_rpi_start("thing", plc_sim_addr, forced_mac_addr)) {
        return -1;
    }

    self_path = argv[0];

    // Init Thing's FLDT implementation
    CHECK_RET(!vs_sdmp_register_service(vs_sdmp_fldt_client()), -1, "FLDT server is not registered");
    FLDT_CHECK(vs_fldt_init(&fw_ctx, &tl_ctx), "Unable to initialize Thing's FLDT implementation");

    vs_rpi_app_info("Thing", fw_ctx, manufacture_id, device_type);

    // Start app
#if SIMULATOR
    if (_test_message[0] != 0) { //-V547
        VS_LOG_INFO(_test_message);
    }
#endif

    // Sleep until CTRL_C
    vs_rpi_hal_sleep_until_stop();

    VS_LOG_INFO("\n\n\nTerminating application ...");

    vs_fldt_destroy_client();

    int res = vs_rpi_hal_update(argc, argv);

    return res;
}

/******************************************************************************/
