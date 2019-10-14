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

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/prvs/prvs-server.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/vs-softhsm/vs-softhsm.h>
#include <hal/rpi-global-hal.h>
#include <trust_list-config.h>

#include "helpers/input-params.h"

// Implementation variables
static vs_hsm_impl_t *hsm_impl = NULL;
static vs_netif_t *netif_impl = NULL;
static vs_storage_op_ctx_t tl_storage_impl;
static vs_storage_op_ctx_t slots_storage_impl;

/******************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_descriptor_hal(void *descriptor, size_t buf_sz) {
    return VS_CODE_ERR_NOT_IMPLEMENTED;
}

/******************************************************************************/
int
main(int argc, char *argv[]) {
    vs_mac_addr_t forced_mac_addr;
    vs_status_e ret_code;

    // Device parameters
    vs_device_manufacture_id_t manufacture_id = {0};
    vs_device_type_t device_type = {0};
    vs_device_serial_t serial = {0};

    // Device specific parameters
#if GATEWAY
    const char *title = "Gateway initializer";
    const char *devices_dir = "gateway";
    uint32_t device_roles = VS_SDMP_DEV_GATEWAY;
#else
    const char *title = "Thing initializer";
    const char *devices_dir = "thing";
    uint32_t device_roles = VS_SDMP_DEV_THING;
#endif

    // Initialize Logger module
    vs_logger_init(VS_LOGLEV_DEBUG);

    // Get input parameters
    STATUS_CHECK(vs_process_commandline_params(argc, argv, &forced_mac_addr), "Cannot read input parameters");

    // Print title
    vs_rpi_print_title(title, argv[0], MANUFACTURE_ID, DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_rpi_prepare_storage(devices_dir, forced_mac_addr), "Cannot prepare storage");

    // Prepare device parameters
    vs_rpi_get_serial(serial, forced_mac_addr);
    vs_rpi_create_data_array(manufacture_id, MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_rpi_create_data_array(device_type, DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);


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

    // Soft HSM
    hsm_impl = vs_softhsm_impl(&slots_storage_impl);

    //
    // ---------- Initialize Virgil SDK modules ----------
    //

    // Provision module
    STATUS_CHECK(vs_provision_init(hsm_impl), "Cannot initialize Provision module");

    // TrustList module
    vs_tl_init(&tl_storage_impl, hsm_impl);

    // SDMP module
    STATUS_CHECK(vs_sdmp_init(netif_impl, manufacture_id, device_type, serial, device_roles),
                 "Unable to initialize SDMP module");

    //
    // ---------- Register SDMP services ----------
    //

    //  PRVS service
    STATUS_CHECK_RET(vs_sdmp_register_service(vs_sdmp_prvs_server(hsm_impl)), "Cannot register PRVS service");


    //
    // ---------- Application work ----------
    //

    // Sleep until CTRL_C
    vs_rpi_hal_sleep_until_stop();


    //
    // ---------- Terminate application ----------
    //

    VS_LOG_INFO("\n\n\n");
    VS_LOG_INFO("Terminating application ...");


    // Deinitialize Virgil SDK modules
    vs_sdmp_deinit();

terminate:

    return VS_CODE_OK;
}

/******************************************************************************/
