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

/******************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_descriptor_hal(void *descriptor, size_t buf_sz) {

    vs_status_e res = VS_CODE_OK;
    //    assert(descriptor);
    //    CHECK_NOT_ZERO_RET(descriptor, -1);
    //    CHECK_RET(buf_sz == sizeof(vs_firmware_descriptor_t), VS_CODE_ERR_INCORRECT_ARGUMENT, "Buffer too small");
    //
    //    vs_storage_op_ctx_t fw_update_ctx;
    //    vs_rpi_storage_impl_func(&fw_update_ctx.impl_func);
    //    assert(fw_update_ctx.impl_func.deinit);
    //
    //    fw_update_ctx.impl_data = vs_rpi_storage_impl_data_init(vs_rpi_get_firmware_dir());
    //
    //    res = vs_load_own_firmware_descriptor(THING_MANUFACTURE_ID, THING_DEVICE_MODEL, &fw_update_ctx, descriptor);
    //
    //    fw_update_ctx.impl_func.deinit(fw_update_ctx.impl_data);

    return res;
}
