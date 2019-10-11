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

#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/firmware/update_fw_interface.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/update_tl_interface.h>
#include <fldt-impl-tg.h>
#include <limits.h>
#include <hal/rpi-global-hal.h>
#include <hal/storage/rpi-storage-hal.h>
#include <trust_list-config.h>
#include <update-config.h>

/******************************************************************************/
static void
_got_file(vs_update_file_type_t *file_type,
          const vs_update_file_version_t *prev_file_ver,
          const vs_update_file_version_t *new_file_ver,
          vs_update_interface_t *update_interface,
          const vs_mac_addr_t *gateway,
          bool successfully_updated) {

    char file_descr[FLDT_FILEVER_BUF];
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
    VS_LOG_INFO("Gateway : " FLDT_GATEWAY_TEMPLATE, FLDT_GATEWAY_ARG(*gateway));
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
vs_status_e
vs_fldt_thing_firmware_init(void) {
    static const char *manufacturer_id = THING_MANUFACTURE_ID;
    static const char *device_id = THING_DEVICE_MODEL;
    vs_update_file_type_t file_type;
    vs_status_e ret_code;
    uint8_t *filetype_manufacture_id = file_type.add_info;
    uint8_t *filetype_device_type = file_type.add_info + VS_DEVICE_MANUFACTURE_ID_SIZE;
    //
    STATUS_CHECK_RET(vs_update_firmware_init(&_fw_update_ctx, &_fw_storage_ctx),
                     "Unable to initialize Firmware's Update context");

    memset(&file_type, 0, sizeof(file_type));

    file_type.type = VS_UPDATE_FIRMWARE;
    //        _make_firmware_add_data_element(filetype_manufacture_id, manufacturer_id, VS_DEVICE_MANUFACTURE_ID_SIZE);
    //        _make_firmware_add_data_element(filetype_device_type, device_id, VS_DEVICE_TYPE_SIZE);

        STATUS_CHECK_RET(vs_fldt_update_client_file_type(&file_type, &_fw_update_ctx), "Unable to add firmware file
        type");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_fldt_thing_trust_list_init(void) {
    //    vs_update_file_type_t file_type;
    //    vs_status_e ret_code;
    //
    //    STATUS_CHECK_RET(vs_update_trust_list_init(&_tl_update_ctx, &_tl_storage_ctx),
    //                     "Unable to initialize Trust List's Update context");
    //
    //    memset(&file_type, 0, sizeof(file_type));
    //    file_type.file_type_id = VS_UPDATE_TRUST_LIST;
    //
    //    STATUS_CHECK_RET(vs_fldt_update_client_file_type(&file_type, &_tl_update_ctx),
    //                     "Unable to add Trust List file type");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_fldt_thing_init(void) {
    vs_status_e ret_code;

    VS_LOG_DEBUG("[FLDT] Initialization");

    STATUS_CHECK_RET(vs_fldt_init_client(_got_file), "Unable to initialize FLDT client");
    STATUS_CHECK_RET(vs_fldt_thing_firmware_init(), "Unable to initialize Firmware");
    STATUS_CHECK_RET(vs_fldt_thing_trust_list_init(), "Unable to initialize Trust List");

    VS_LOG_DEBUG("[FLDT] Successfully initialized");

    return VS_CODE_OK;
}

/******************************************************************************/
