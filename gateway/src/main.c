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
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/fldt/fldt-server.h>
#include <virgil/iot/vs-curl-http/curl-http.h>
#include <virgil/iot/protocols/sdmp/info/info-server.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/vs-softhsm/vs-softhsm.h>
#include <trust_list-config.h>
#include <update-config.h>
#include "threads/main-thread.h"
#include "helpers/app-helpers.h"
#include "helpers/file-cache.h"
#include "helpers/app-storage.h"
#include "sdk-impl/firmware/firmware-nix-impl.h"
#include <virgil/iot/vs-aws-message-bin/aws-message-bin.h>
#include <threads/message-bin-thread.h>

/******************************************************************************/
static vs_status_e
_add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx) {
    switch (file_type->type) {
    case VS_UPDATE_FIRMWARE:
        *update_ctx = vs_firmware_update_ctx();
        break;
    case VS_UPDATE_TRUST_LIST:
        *update_ctx = vs_tl_update_ctx();
        break;
    default:
        VS_LOG_ERROR("Unsupported file type : %d", file_type->type);
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
int
main(int argc, char *argv[]) {
    vs_mac_addr_t forced_mac_addr;
    const vs_sdmp_service_t *sdmp_info_server;
    const vs_sdmp_service_t *sdmp_fldt_server;
    int res = -1;

    // Implementation variables
    vs_hsm_impl_t *hsm_impl = NULL;
    vs_netif_t *netif_impl = NULL;
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;
    vs_storage_op_ctx_t fw_storage_impl;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id = {0};
    vs_device_type_t device_type = {0};
    vs_device_serial_t serial = {0};

    // Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Get input parameters
    STATUS_CHECK(vs_app_commandline_params(argc, argv, &forced_mac_addr), "Cannot read input parameters");

    // Prepare device parameters
    vs_app_get_serial(serial, forced_mac_addr);
    vs_app_str_to_bytes(manufacture_id, GW_MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_app_str_to_bytes(device_type, GW_DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);

    // Set device info path
    vs_firmware_nix_set_info(argv[0], manufacture_id, device_type);

    // Print title
    vs_app_print_title("Gateway", argv[0], GW_MANUFACTURE_ID, GW_DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_app_prepare_storage("gateway", forced_mac_addr), "Cannot prepare storage");

    // Enable cached file IO
    vs_file_cache_enable(true);

    //
    // ---------- Create implementations ----------
    //

    // Network interface
    netif_impl = vs_app_create_netif_impl(forced_mac_addr);

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create TrustList storage");

    // Firmware storage
    STATUS_CHECK(vs_app_storage_init_impl(&fw_storage_impl, vs_app_firmware_dir(), VS_MAX_FIRMWARE_UPDATE_SIZE),
                 "Cannot create TrustList storage");

    // Soft HSM
    hsm_impl = vs_softhsm_impl(&slots_storage_impl);

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    STATUS_CHECK(vs_provision_init(&tl_storage_impl, hsm_impl), "Cannot initialize Provision module");

    // Firmware module
    STATUS_CHECK(vs_firmware_init(&fw_storage_impl, hsm_impl, manufacture_id, device_type),
                 "Unable to initialize Firmware module");

    // SDMP module
    STATUS_CHECK(vs_sdmp_init(netif_impl, manufacture_id, device_type, serial, VS_SDMP_DEV_THING),
                 "Unable to initialize SDMP module");

    // Cloud module
    STATUS_CHECK(vs_cloud_init(vs_curl_http_impl(), vs_aws_message_bin_impl(), hsm_impl),
                 "Unable to initialize Cloud module");

    // Register message bin default handlers
    STATUS_CHECK(vs_message_bin_register_handlers(), "Unable to register message bin handlers");

    //
    // ---------- Register SDMP services ----------
    //

    //  INFO server service
    sdmp_info_server = vs_sdmp_info_server(&tl_storage_impl, &fw_storage_impl);
    STATUS_CHECK(vs_sdmp_register_service(sdmp_info_server), "Cannot register FLDT server service");

    //  FLDT server service
    sdmp_fldt_server = vs_sdmp_fldt_server(&forced_mac_addr, _add_filetype);
    STATUS_CHECK(vs_sdmp_register_service(sdmp_fldt_server), "Cannot register FLDT server service");
    STATUS_CHECK(vs_fldt_server_add_file_type(vs_firmware_update_file_type(), vs_firmware_update_ctx(), false),
                 "Unable to add firmware file type");
    STATUS_CHECK(vs_fldt_server_add_file_type(vs_tl_update_file_type(), vs_tl_update_ctx(), false),
                 "Unable to add firmware file type");


    //
    // ---------- Application work ----------
    //

    // Init gateway object
    vs_gateway_ctx_init(&forced_mac_addr);

    // Start app
    vs_main_start_threads();

    // Sleep until CTRL_C
    vs_app_sleep_until_stop();


    //
    // ---------- Terminate application ----------
    //

terminate:

    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating application ...");


    // Deinitialize Virgil SDK modules
    vs_sdmp_deinit();

    // Deinit provision
    vs_provision_deinit();

    res = vs_firmware_nix_update(argc, argv);

    // Clean File cache
    vs_file_cache_clean();

    return res;
}

/******************************************************************************/
void
vs_impl_msleep(size_t msec) {
    usleep(msec * 1000);
}

/******************************************************************************/
void
vs_impl_device_serial(vs_device_serial_t serial_number) {
    memcpy(serial_number, vs_sdmp_device_serial(), VS_DEVICE_SERIAL_SIZE);
}

/******************************************************************************/
