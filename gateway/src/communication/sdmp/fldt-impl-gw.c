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

#include <assert.h>
#include <virgil/iot/protocols/sdmp/fldt/fldt-server.h>
#include <virgil/iot/status_code/status_code.h>
#include <fldt-impl-gw.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/firmware/update_fw_interface.h>
#include <virgil/iot/trust_list/update_tl_interface.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>

/******************************************************************************/
static vs_status_e
vs_fldt_add_filetype(const vs_update_file_type_t *file_type, vs_update_interface_t **update_ctx) {
    assert(file_type);

    switch (file_type->type) {
    case VS_UPDATE_FIRMWARE:
        //        *update_ctx = &_fw_update_ctx;
        break;

    case VS_UPDATE_TRUST_LIST:
        //        *update_ctx = &_tl_update_ctx;
        break;

    default:
        VS_LOG_ERROR("[FLDT:add_filetype] Unsupported file type %d", file_type->type);
        return VS_CODE_ERR_UNSUPPORTED_PARAMETER;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_fldt_gateway_trust_list_init(void) {
    vs_update_file_type_t file_type;
    //    vs_status_e ret_code;

    //    STATUS_CHECK_RET(vs_update_trust_list_init(&_tl_update_ctx, &_tl_storage_ctx),
    //                     "Unable to initialize Trust List's Update context");

    memset(&file_type, 0, sizeof(file_type));
    file_type.type = VS_UPDATE_TRUST_LIST;

    //    STATUS_CHECK_RET(vs_fldt_update_server_file_type(&file_type, &_tl_update_ctx, true),
    //                     "Unable to add Trust List file type");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_fldt_gateway_init(const vs_mac_addr_t *gateway_mac) {
    vs_status_e ret_code;

    VS_LOG_DEBUG("[FLDT] Initialization");

    STATUS_CHECK_RET(vs_fldt_init_server(gateway_mac, vs_fldt_add_filetype),
                     "Unable to initialize FLDT's server service");

    //    STATUS_CHECK_RET(vs_update_firmware_init(&_fw_update_ctx, &_fw_storage_ctx),
    //                     "Unable to initialize Firmware's Update context");

    STATUS_CHECK_RET(vs_fldt_gateway_trust_list_init(), "Unable to initialize Trust List");

    VS_LOG_DEBUG("[FLDT] Successfully initialized");

    return VS_CODE_OK;
}
