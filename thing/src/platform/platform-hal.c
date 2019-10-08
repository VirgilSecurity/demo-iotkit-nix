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
#include <string.h>
#include <global-hal.h>
#include <virgil/iot/firmware/firmware.h>
#include "hal/storage/rpi-storage-hal.h"
#include <hal/rpi-global-hal.h>

//// TODO: Need to use real descriptor, which can be obtain from footer of self image
// static vs_firmware_descriptor_t _descriptor;
// static bool _is_descriptor_ready = false;
//
///******************************************************************************/
// static void
//_create_field(uint8_t *dst, const char *src, size_t elem_buf_size) {
//    size_t pos;
//    size_t len;
//
//    assert(src && *src);
//    assert(elem_buf_size);
//
//    len = strlen(src);
//    for (pos = 0; pos < len && pos < elem_buf_size; ++pos, ++src, ++dst) {
//        *dst = *src;
//    }
//}

/******************************************************************************/
int
vs_global_hal_get_own_firmware_descriptor(void *descriptor) {

    int res;
    assert(descriptor);
    CHECK_NOT_ZERO_RET(descriptor, -1);

    vs_storage_op_ctx_t fw_update_ctx;
    vs_rpi_get_storage_impl(&fw_update_ctx.impl);
    assert(fw_update_ctx.impl.deinit);

    fw_update_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_firmware_dir());

    res = vs_load_own_firmware_descriptor(THING_MANUFACTURE_ID, THING_DEVICE_MODEL, &fw_update_ctx, descriptor);

    fw_update_ctx.impl.deinit(fw_update_ctx.storage_ctx);

    return res;

    //    if (!_is_descriptor_ready) {
    //        vs_firmware_descriptor_t desc;
    //        vs_fw_manufacture_id_t manufacture_id;
    //        vs_fw_device_type_t device_type;
    //
    //        memset(&desc, 0, sizeof(vs_firmware_descriptor_t));
    //
    //        _create_field(manufacture_id, THING_MANUFACTURE_ID, MANUFACTURE_ID_SIZE);
    //        _create_field(device_type, THING_DEVICE_MODEL, DEVICE_TYPE_SIZE);
    //
    //        if (VS_CODE_OK != vs_firmware_load_firmware_descriptor(&fw_update_ctx, manufacture_id, device_type,
    //        &desc)) {
    //            VS_LOG_WARNING("Unable to obtain Firmware's descriptor. Use default");
    //            memset(&_descriptor, 0, sizeof(vs_firmware_descriptor_t));
    //            _create_field(_descriptor.info.manufacture_id, THING_MANUFACTURE_ID, MANUFACTURE_ID_SIZE);
    //            _create_field(_descriptor.info.device_type, THING_DEVICE_MODEL, DEVICE_TYPE_SIZE);
    //        } else {
    //            memcpy(&_descriptor, &desc, sizeof(vs_firmware_descriptor_t));
    //        }
    //        _is_descriptor_ready = true;
    //    }
    //
    //    memcpy(descriptor, &_descriptor, sizeof(vs_firmware_descriptor_t));
    //    return 0;
}
