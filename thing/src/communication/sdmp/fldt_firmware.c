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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp/fldt_client.h>
#include <update-config.h>
#include <fldt_implementation.h>
#include <hal/storage/rpi-storage-hal.h>

vs_storage_op_ctx_t _storage_ctx;

/******************************************************************************/
static void
_make_firmware_add_data_element(uint8_t *dst, const char *src, size_t elem_buf_size) {
    size_t pos;
    size_t len;

    assert(src && *src);
    assert(elem_buf_size);

    len = strlen(src);
    for (pos = 0; pos < len && pos < elem_buf_size; ++pos, ++src, ++dst) {
        *dst = *src;
    }
}

/******************************************************************************/
vs_fldt_ret_code_e
vs_fldt_firmware_init(void) {
    static const char *manufacturer_id = MANUFACTURER_ID;
    static const char *device_id = DEVICE_ID;
    vs_fldt_file_type_t file_type;
    vs_fldt_ret_code_e fldt_ret_code;
    vs_fldt_fw_add_info_t *fw_add_data = (vs_fldt_fw_add_info_t *)file_type.add_info;

    VS_LOG_INFO("Firmware's manufacture ID = \"%s\", device type = \"%s\"", manufacturer_id, device_id);

    vs_rpi_get_storage_impl(&_storage_ctx.impl);
    _storage_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_firmware_dir());
    _storage_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;

    memset(&file_type, 0, sizeof(file_type));

    file_type.file_type_id = VS_UPDATE_FIRMWARE;
    _make_firmware_add_data_element(fw_add_data->manufacture_id, manufacturer_id, MANUFACTURE_ID_SIZE);
    _make_firmware_add_data_element(fw_add_data->device_type, device_id, DEVICE_TYPE_SIZE);

    FLDT_CHECK(vs_fldt_update_client_file_type(&file_type, &_storage_ctx), "Unable to add firmware file type");

    return VS_FLDT_ERR_OK;
}
