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
#include <virgil/iot/vs-curl-http/curl-http.h>
#include <virgil/iot/protocols/sdmp/info/info-server.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/vs-softhsm/vs-softhsm.h>
#include <trust_list-config.h>
#include <update-config.h>
#include "gateway.h"
#include "helpers/input-params.h"
#include "fldt-impl-gw.h"
#include "hal/rpi-global-hal.h"
#include "hal/storage/rpi-file-cache.h"

// Implementation variables
static vs_hsm_impl_t *hsm_impl = NULL;
static vs_netif_t *netif_impl = NULL;
static vs_storage_op_ctx_t tl_storage_impl;
static vs_storage_op_ctx_t slots_storage_impl;
static vs_storage_op_ctx_t fw_storage_impl;

/******************************************************************************/
int
main(int argc, char *argv[]) {
    vs_mac_addr_t forced_mac_addr;
    vs_status_e ret_code;
    int res = -1;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id = {0};
    vs_device_type_t device_type = {0};
    vs_device_serial_t serial = {0};

    // Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Get input parameters
    STATUS_CHECK(vs_process_commandline_params(argc, argv, &forced_mac_addr), "Cannot read input parameters");

    // Print title
    vs_rpi_print_title("Gateway", argv[0], GW_MANUFACTURE_ID, GW_DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_rpi_prepare_storage("gateway", forced_mac_addr), "Cannot prepare storage");
    // Enable cached file IO
    vs_file_cache_enable(true);

    // Prepare device parameters
    vs_rpi_get_serial(serial, forced_mac_addr);
    vs_rpi_create_data_array(manufacture_id, GW_MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_rpi_create_data_array(device_type, GW_DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);

    // Init cloud library
    CHECK_RET(VS_CODE_OK == vs_cloud_init(vs_curl_http_impl()), -3, "Unable to initialize cloud");

    //
    // ---------- Create implementations ----------
    //

    // Network interface
    netif_impl = vs_rpi_create_netif_impl(forced_mac_addr);

    // TrustList storage
    STATUS_CHECK(vs_rpi_create_storage_impl(&tl_storage_impl, vs_rpi_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_rpi_create_storage_impl(&slots_storage_impl, vs_rpi_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create TrustList storage");

    // Firmware storage
    STATUS_CHECK(vs_rpi_create_storage_impl(&fw_storage_impl, vs_rpi_slots_dir(), VS_MAX_FIRMWARE_UPDATE_SIZE),
                 "Cannot create TrustList storage");

    // Soft HSM
    hsm_impl = vs_softhsm_impl(&slots_storage_impl);

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    STATUS_CHECK(vs_provision_init(hsm_impl), "Cannot initialize Provision module");

    // TrustList module
    vs_tl_init(&tl_storage_impl, hsm_impl);

    // Firmware module
    vs_firmware_init(&fw_storage_impl, hsm_impl, manufacture_id, device_type);

    // SDMP module
    STATUS_CHECK(vs_sdmp_init(netif_impl, manufacture_id, device_type, serial, VS_SDMP_DEV_THING),
                 "Unable to initialize SDMP module");

    //
    // ---------- Register SDMP services ----------
    //

    //  INFO server service
    STATUS_CHECK_RET(vs_sdmp_register_service(vs_sdmp_info_server(&tl_storage_impl, &fw_storage_impl)),
                     "Cannot register FLDT client service");

    //  FLDT client service
    STATUS_CHECK_RET(vs_sdmp_register_service(vs_sdmp_fldt_client(_on_file_updated)),
                     "Cannot register FLDT client service");
    STATUS_CHECK_RET(vs_fldt_client_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx()),
                     "Unable to add firmware file type");
    STATUS_CHECK_RET(vs_fldt_client_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx()),
                     "Unable to add firmware file type");


    //
    // ---------- Application work ----------
    //

#if SIMULATOR
    if (_test_message[0] != 0) { //-V547
        VS_LOG_INFO(_test_message);
    }
#endif

    // Sleep until CTRL_C
    vs_rpi_hal_sleep_until_stop();


    //
    // ---------- Terminate application ----------
    //

    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating application ...");


    // Deinitialize Virgil SDK modules
    vs_sdmp_deinit();

    // TODO: Move to vs_sdmp_deinit
    vs_fldt_destroy_client();

    res = vs_rpi_hal_update((const char *)THING_MANUFACTURE_ID, (const char *)THING_DEVICE_MODEL, argc, argv);

terminate:

    return res;

//
//    // Setup forced mac address
//    vs_mac_addr_t forced_mac_addr;
//
//    if (0 != vs_process_commandline_params(argc, argv, &forced_mac_addr)) {
//        return -1;
//    }
//
//    if (0 != vs_rpi_start("gateway",
//                          argv[0],
//                          forced_mac_addr,
//                          (const char *)GW_MANUFACTURE_ID,
//                          (const char *)GW_DEVICE_MODEL,
//                          VS_SDMP_DEV_GATEWAY | VS_SDMP_DEV_LOGGER,
//                          false)) {
//        return -1;
//    }
//
//    VS_LOG_INFO("%s", argv[0]);
//    self_path = argv[0];
//
//    // Enable cached file IO
//    vs_file_cache_enable(true);
//
//    // Init Thing's FLDT implementation
//    CHECK_RET(!vs_sdmp_register_service(vs_sdmp_fldt_server()), -1, "FLDT server is not registered");
//    CHECK_RET(!vs_fldt_gateway_init(&forced_mac_addr), -2, "Unable to initialize FLDT");
//
//    // Init gateway object
//    init_gateway_ctx(&forced_mac_addr);
//
//    // Start app
//    start_gateway_threads();
//
//    // Sleep until CTRL_C
//    vs_rpi_hal_sleep_until_stop();
//
//    VS_LOG_INFO("Terminating application ...");
//
//    vs_sdmp_deinit();
//
//    int res = vs_rpi_hal_update((const char *)GW_MANUFACTURE_ID, (const char *)GW_DEVICE_MODEL, argc, argv);
//
//    // Clean File cache
//    vs_file_cache_clean();
//
//    return res;
}

/******************************************************************************/
