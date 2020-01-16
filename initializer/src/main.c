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

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/prvs/prvs-server.h>
#include <virgil/iot/protocols/snap/info/info-server.h>
#include <virgil/iot/protocols/snap/cfg/cfg-server.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/vs-soft-secmodule/vs-soft-secmodule.h>
#include <trust_list-config.h>

#include "helpers/app-helpers.h"
#include "helpers/app-storage.h"

#include "sdk-impl/netif/netif-udp-broadcast.h"
#include "sdk-impl/netif/packets-queue.h"

static vs_status_e
vs_snap_cfg_config(const vs_cfg_configuration_t *configuration);

/******************************************************************************/
int
main(int argc, char *argv[]) {
    vs_mac_addr_t forced_mac_addr;
    const vs_snap_service_t *snap_prvs_server;
    const vs_snap_service_t *snap_info_server;
    const vs_snap_service_t *snap_cfg_server;
    vs_status_e ret_code;

    // Implementation variables
    vs_secmodule_impl_t *secmodule_impl = NULL;
    vs_netif_t *netif_impl = NULL;
    vs_storage_op_ctx_t tl_storage_impl;
    vs_storage_op_ctx_t slots_storage_impl;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id = {0};
    vs_device_type_t device_type = {0};
    vs_device_serial_t serial = {0};

    // Device specific parameters
#if GATEWAY
    const char *title = "Gateway initializer";
    const char *devices_dir = "gateway";
    uint32_t device_roles = (uint32_t)VS_SNAP_DEV_GATEWAY | (uint32_t)VS_SNAP_DEV_INITIALIZER;
#else
    const char *title = "Thing initializer";
    const char *devices_dir = "thing";
    uint32_t device_roles = (uint32_t)VS_SNAP_DEV_THING | (uint32_t)VS_SNAP_DEV_INITIALIZER;
#endif

    // Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Get input parameters
    STATUS_CHECK(vs_app_get_mac_from_commandline_params(argc, argv, &forced_mac_addr), "Cannot read input parameters");

    // Print title
    vs_app_print_title(title, argv[0], MANUFACTURE_ID, DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_app_prepare_storage(devices_dir, forced_mac_addr), "Cannot prepare storage");

    // Prepare device parameters
    vs_app_get_serial(serial, forced_mac_addr);
    vs_app_str_to_bytes(manufacture_id, MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_app_str_to_bytes(device_type, DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);


    //
    // ---------- Create implementations ----------
    //

    // Network interface
    vs_packets_queue_init(vs_snap_default_processor);
    netif_impl = vs_hal_netif_udp_bcast(forced_mac_addr);

    // TrustList storage
    STATUS_CHECK(vs_app_storage_init_impl(&tl_storage_impl, vs_app_trustlist_dir(), VS_TL_STORAGE_MAX_PART_SIZE),
                 "Cannot create TrustList storage");

    // Slots storage
    STATUS_CHECK(vs_app_storage_init_impl(&slots_storage_impl, vs_app_slots_dir(), VS_SLOTS_STORAGE_MAX_SIZE),
                 "Cannot create TrustList storage");

    // Soft Security Module
    secmodule_impl = vs_soft_secmodule_impl(&slots_storage_impl);

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    ret_code = vs_provision_init(&tl_storage_impl, secmodule_impl);
    if (VS_CODE_OK != ret_code && VS_CODE_ERR_NOINIT != ret_code) {
        VS_LOG_ERROR("Cannot initialize Provision module");
        goto terminate;
    }

    // SNAP module
    STATUS_CHECK(vs_snap_init(netif_impl, vs_packets_queue_add, manufacture_id, device_type, serial, device_roles),
                 "Unable to initialize SNAP module");

    //
    // ---------- Register SNAP services ----------
    //

    //  INFO server service
    snap_info_server = vs_snap_info_server(NULL);
    STATUS_CHECK(vs_snap_register_service(snap_info_server), "Cannot register INFO server service");

    //  _CFG service
    snap_cfg_server = vs_snap_cfg_server(vs_snap_cfg_config);
    STATUS_CHECK(vs_snap_register_service(snap_cfg_server), "Cannot register CFG service");

    //  PRVS service
    snap_prvs_server = vs_snap_prvs_server(secmodule_impl);
    STATUS_CHECK(vs_snap_register_service(snap_prvs_server), "Cannot register PRVS service");


    //
    // ---------- Application work ----------
    //

    // Sleep until CTRL_C
    vs_app_sleep_until_stop();


    //
    // ---------- Terminate application ----------
    //
terminate:

    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating application ...");

    // Deinit Virgil SDK modules
    vs_snap_deinit();

    // Deinit provision
    vs_provision_deinit();

    // Deinit Soft Security Module
    vs_soft_secmodule_deinit();

    // Deinit packets Queue
    vs_packets_queue_deinit();

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_firmware_install_prepare_space_hal(void) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_firmware_install_append_data_hal(const void *data, uint16_t data_sz) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_footer_hal(void *footer, size_t footer_sz) {

    assert(footer);
    assert(footer_sz);
    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(footer_sz, VS_CODE_ERR_INCORRECT_ARGUMENT);

    memset(footer, 0, footer_sz);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
vs_snap_cfg_config(const vs_cfg_configuration_t *configuration) {
    CHECK_NOT_ZERO_RET(configuration, VS_CODE_ERR_INCORRECT_ARGUMENT);
    VS_LOG_DEBUG("Configure :");
    VS_LOG_DEBUG("     ssid : %s", configuration->ssid);
    VS_LOG_DEBUG("     pass : %s", configuration->pass);
    VS_LOG_DEBUG("     account : %s", configuration->account);
    return VS_CODE_OK;
}

/******************************************************************************/
