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

#include <stdbool.h>
#include <stdio.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>

#include <global-hal.h>
#include "hal/storage/rpi-storage-hal.h"

typedef struct {
    char *dir;

} vs_rpi_storage_ctx_t;

/******************************************************************************/
static void
_data_to_hex(const uint8_t *_data, uint32_t _len, uint8_t *_out_data, uint32_t *_in_out_len) {
    const uint8_t hex_str[] = "0123456789abcdef";
    VS_IOT_ASSERT(_in_out_len);
    VS_IOT_ASSERT(_data);
    VS_IOT_ASSERT(_out_data);

    VS_IOT_ASSERT(*_in_out_len >= _len * 2 + 1);

    *_in_out_len = _len * 2 + 1;
    _out_data[*_in_out_len - 1] = 0;
    size_t i;

    for (i = 0; i < _len; i++) {
        _out_data[i * 2 + 0] = hex_str[(_data[i] >> 4) & 0x0F];
        _out_data[i * 2 + 1] = hex_str[(_data[i]) & 0x0F];
    }
}

/******************************************************************************/
vs_storage_hal_ctx_t
vs_rpi_storage_init(const char *relative_dir) {
    CHECK_NOT_ZERO_RET(relative_dir, NULL);
    vs_rpi_storage_ctx_t *ctx = VS_IOT_CALLOC(1, sizeof(vs_rpi_storage_ctx_t));
    CHECK_NOT_ZERO_RET(ctx, NULL);

    ctx->dir = (char *)VS_IOT_CALLOC(1, strlen(relative_dir) + 1);
    if (NULL == ctx->dir) {
        VS_LOG_ERROR("Can't allocate memory");
        VS_IOT_FREE(ctx);
        return NULL;
    }

    VS_IOT_STRCPY(ctx->dir, relative_dir);

    return ctx;
}

/******************************************************************************/
int
vs_rpi_storage_deinit_hal(vs_storage_hal_ctx_t storage_ctx) {
    CHECK_NOT_ZERO_RET(storage_ctx, VS_STORAGE_ERROR_PARAMS);
    vs_rpi_storage_ctx_t *ctx = (vs_rpi_storage_ctx_t *)storage_ctx;
    CHECK_NOT_ZERO_RET(ctx->dir, VS_STORAGE_ERROR_PARAMS);

    VS_IOT_FREE(ctx->dir);
    VS_IOT_FREE(ctx);
    return VS_STORAGE_OK;
}

/******************************************************************************/
vs_storage_file_t
vs_rpi_storage_open_hal(const vs_storage_hal_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    CHECK_NOT_ZERO_RET(id, NULL);
    CHECK_NOT_ZERO_RET(storage_ctx, NULL);
    vs_rpi_storage_ctx_t *ctx = (vs_rpi_storage_ctx_t *)storage_ctx;
    CHECK_NOT_ZERO_RET(ctx->dir, NULL);

    uint32_t len = sizeof(vs_storage_element_id_t) * 2 + 1;
    uint8_t *file = (uint8_t *)VS_IOT_CALLOC(1, len);
    CHECK_NOT_ZERO_RET(file, NULL);

    _data_to_hex(id, sizeof(vs_storage_element_id_t), file, &len);

    return file;
}

/******************************************************************************/
int
vs_rpi_storage_close_hal(const vs_storage_hal_ctx_t storage_ctx, vs_storage_file_t file) {
    CHECK_NOT_ZERO_RET(file, VS_STORAGE_ERROR_PARAMS);

    VS_IOT_FREE(file);

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_rpi_storage_save_hal_t(const vs_storage_hal_ctx_t storage_ctx,
                          const vs_storage_file_t file,
                          size_t offset,
                          const uint8_t *data,
                          size_t data_sz) {

    CHECK_NOT_ZERO_RET(data, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(file, VS_STORAGE_ERROR_PARAMS);
    vs_rpi_storage_ctx_t *ctx = (vs_rpi_storage_ctx_t *)storage_ctx;

    return vs_rpi_write_file_data(ctx->dir, (char *)file, offset, data, data_sz) ? VS_STORAGE_OK
                                                                                 : VS_STORAGE_ERROR_GENERAL;
}

/******************************************************************************/
int
vs_rpi_storage_load_hal(const vs_storage_hal_ctx_t storage_ctx,
                        const vs_storage_file_t file,
                        size_t offset,
                        uint8_t *out_data,
                        size_t data_sz) {
    size_t read_sz;
    CHECK_NOT_ZERO_RET(out_data, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(file, VS_STORAGE_ERROR_PARAMS);
    vs_rpi_storage_ctx_t *ctx = (vs_rpi_storage_ctx_t *)storage_ctx;
    CHECK_NOT_ZERO_RET(ctx->dir, VS_STORAGE_ERROR_PARAMS);

    if (vs_rpi_read_file_data(ctx->dir, (char *)file, offset, out_data, data_sz, &read_sz) && read_sz == data_sz) {
        return VS_STORAGE_OK;
    }

    return VS_STORAGE_ERROR_GENERAL;
}

/*******************************************************************************/
int
vs_rpi_storage_file_size_hal(const vs_storage_hal_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    CHECK_NOT_ZERO_RET(id, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_STORAGE_ERROR_PARAMS);
    vs_rpi_storage_ctx_t *ctx = (vs_rpi_storage_ctx_t *)storage_ctx;
    CHECK_NOT_ZERO_RET(ctx->dir, VS_STORAGE_ERROR_PARAMS);

    uint32_t len = sizeof(vs_storage_element_id_t) * 2 + 1;
    uint8_t file[len];

    _data_to_hex(id, sizeof(vs_storage_element_id_t), file, &len);

    return vs_rpi_get_file_len(ctx->dir, (char *)file);
}

/******************************************************************************/
int
vs_rpi_storage_del_hal(const vs_storage_hal_ctx_t storage_ctx, const vs_storage_element_id_t id) {
    CHECK_NOT_ZERO_RET(id, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO_RET(storage_ctx, VS_STORAGE_ERROR_PARAMS);
    vs_rpi_storage_ctx_t *ctx = (vs_rpi_storage_ctx_t *)storage_ctx;
    CHECK_NOT_ZERO_RET(ctx->dir, VS_STORAGE_ERROR_PARAMS);

    uint32_t len = sizeof(vs_storage_element_id_t) * 2 + 1;
    uint8_t file[len];

    _data_to_hex(id, sizeof(vs_storage_element_id_t), file, &len);

    return vs_rpi_remove_file_data(ctx->dir, (char *)file) ? VS_STORAGE_OK : VS_STORAGE_ERROR_GENERAL;
}

/******************************************************************************/
int
vs_rpi_get_storage_impl(vs_storage_op_impl_t *impl) {
    CHECK_NOT_ZERO_RET(impl, VS_STORAGE_ERROR_PARAMS);

    impl->size = vs_rpi_storage_file_size_hal;
    impl->deinit = vs_rpi_storage_deinit_hal;
    impl->open = vs_rpi_storage_open_hal;
    impl->close = vs_rpi_storage_close_hal;
    impl->save = vs_rpi_storage_save_hal_t;
    impl->load = vs_rpi_storage_load_hal;
    impl->del = vs_rpi_storage_del_hal;
    return VS_STORAGE_OK;
}