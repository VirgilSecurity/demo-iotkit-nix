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
#include <trust_list-config.h>

vs_storage_op_ctx_t _tl_storage_ctx;

/******************************************************************************/
vs_fldt_ret_code_e
vs_fldt_trust_list_init(void) {
    vs_fldt_file_type_t file_type;
    vs_fldt_ret_code_e fldt_ret_code;

    vs_rpi_get_storage_impl(&_tl_storage_ctx.impl);
    _tl_storage_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_trust_list_dir());
    _tl_storage_ctx.file_sz_limit = VS_TL_STORAGE_MAX_PART_SIZE;

    memset(&file_type, 0, sizeof(file_type));

    file_type.file_type_id = VS_UPDATE_TRUST_LIST;

    FLDT_CHECK(vs_fldt_update_client_file_type(&file_type, &_tl_storage_ctx), "Unable to add Trust List file type");

    return VS_FLDT_ERR_OK;
}
