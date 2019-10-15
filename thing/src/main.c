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
#include <virgil/iot/protocols/sdmp/fldt/fldt-client.h>
#include <virgil/iot/protocols/sdmp/info/info-server.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/vs-softhsm/vs-softhsm.h>
#include <trust_list-config.h>
#include <update-config.h>

#include "hal/rpi-global-hal.h"
#include "helpers/input-params.h"
#include "hal/storage/rpi-file-cache.h"

#if SIMULATOR
static const char _test_message[] = TEST_UPDATE_MESSAGE;
#endif

// Implementation variables
static vs_hsm_impl_t *hsm_impl = NULL;
static vs_netif_t *netif_impl = NULL;
static vs_storage_op_ctx_t tl_storage_impl;
static vs_storage_op_ctx_t slots_storage_impl;
static vs_storage_op_ctx_t fw_storage_impl;

static void
_on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated);

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
    vs_rpi_print_title("Thing", argv[0], THING_MANUFACTURE_ID, THING_DEVICE_MODEL);

    // Prepare local storage
    STATUS_CHECK(vs_rpi_prepare_storage("thing", forced_mac_addr), "Cannot prepare storage");
    // Enable cached file IO
    vs_file_cache_enable(true);

    // Prepare device parameters
    vs_rpi_get_serial(serial, forced_mac_addr);
    vs_rpi_create_data_array(manufacture_id, THING_MANUFACTURE_ID, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_rpi_create_data_array(device_type, THING_DEVICE_MODEL, VS_DEVICE_TYPE_SIZE);


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
    STATUS_CHECK(vs_provision_init(&fw_storage_impl, hsm_impl), "Cannot initialize Provision module");

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

    res = vs_rpi_hal_update((const char *)THING_MANUFACTURE_ID, (const char *)THING_DEVICE_MODEL, argc, argv);

terminate:

    return res;
}

/******************************************************************************/

static void
_on_file_updated(vs_update_file_type_t *file_type,
                 const vs_file_version_t *prev_file_ver,
                 const vs_file_version_t *new_file_ver,
                 vs_update_interface_t *update_interface,
                 const vs_mac_addr_t *gateway,
                 bool successfully_updated) {

    char file_descr[512];
    const char *file_type_descr = NULL;

    VS_IOT_ASSERT(update_interface);
    VS_IOT_ASSERT(prev_file_ver);
    VS_IOT_ASSERT(new_file_ver);
    VS_IOT_ASSERT(gateway);

    if (VS_UPDATE_FIRMWARE == file_type->type) {
        file_type_descr = "firmware";
    } else {
        file_type_descr = "trust list";
    }

    VS_LOG_INFO(
            "New %s was loaded and %s : %s",
            file_type_descr,
            successfully_updated ? "successfully installed" : "did not installed successfully",
            update_interface->describe_version(
                    update_interface->storage_context, file_type, new_file_ver, file_descr, sizeof(file_descr), false));
    VS_LOG_INFO("Previous %s : %s",
                file_type,
                update_interface->describe_version(update_interface->storage_context,
                                                   file_type,
                                                   prev_file_ver,
                                                   file_descr,
                                                   sizeof(file_descr),
                                                   false));

    if (file_type->type == VS_UPDATE_FIRMWARE && successfully_updated) {
        vs_rpi_restart();
    }
}

/******************************************************************************/
