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
#include <stdbool.h>
#include <stdio.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>

#include <virgil/iot/hsm/hsm_errors.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/trust_list/tl_hal.h>

#include "gateway_macro.h"
#include "hal/file_io_hal.h"

/******************************************************************************/
int
vs_tl_save_hal(vs_tl_element_info_hal_t *element_info, const uint8_t *in_data, uint16_t data_sz) {
    CHECK_NOT_ZERO_RET(element_info, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO_RET(in_data, VS_HSM_ERR_INVAL);

    char filename[FILENAME_MAX];

    snprintf(filename, sizeof(filename), "%u_%u_%u", element_info->storage_type, element_info->id, element_info->index);

    return vs_gateway_write_file_data(vs_gateway_get_trust_list_dir(), filename, 0, in_data, data_sz)
                   ? VS_HSM_ERR_OK
                   : VS_HSM_ERR_FILE_IO;
}

/******************************************************************************/
int
vs_tl_load_hal(vs_tl_element_info_hal_t *element_info, uint8_t *out_data, uint16_t data_sz) {
    CHECK_NOT_ZERO_RET(element_info, VS_HSM_ERR_INVAL);
    CHECK_NOT_ZERO_RET(out_data, VS_HSM_ERR_INVAL);

    uint16_t out_sz;
    char filename[FILENAME_MAX];

    snprintf(filename, sizeof(filename), "%u_%u_%u", element_info->storage_type, element_info->id, element_info->index);

    // TODO: RETURN REAL SIZE OF READ DATA
    return vs_gateway_read_file_data(vs_gateway_get_trust_list_dir(), filename, 0, out_data, data_sz, &out_sz)
                   ? VS_HSM_ERR_OK
                   : VS_HSM_ERR_FILE_IO;
}

/******************************************************************************/
int
vs_tl_del_hal(vs_tl_element_info_hal_t *element_info) {
    CHECK_NOT_ZERO_RET(element_info, VS_HSM_ERR_INVAL);

    char filename[FILENAME_MAX];

    snprintf(filename, sizeof(filename), "%u_%u_%u", element_info->storage_type, element_info->id, element_info->index);

    return vs_gateway_remove_file_data(vs_gateway_get_trust_list_dir(), filename) ? VS_HSM_ERR_OK : VS_HSM_ERR_FILE_IO;
}
