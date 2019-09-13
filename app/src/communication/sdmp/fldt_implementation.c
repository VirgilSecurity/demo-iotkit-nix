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

#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <fldt_implementation.h>

/******************************************************************************/
vs_fldt_ret_code_e
vs_fldt_add_filetype(const vs_fldt_file_type_t *file_type, vs_storage_op_ctx_t **storage_ctx){
    char file_descr[FLDT_FILEVER_BUF];

    assert(file_type);

    switch(file_type->file_type_id){
    case VS_UPDATE_FIRMWARE : return vs_fldt_add_fw_filetype(file_type, storage_ctx);
    default :
        VS_LOG_ERROR("[FLDT:add_filetype] Unsupported file type %s", vs_fldt_file_type_descr(file_descr, file_type));
        return VS_FLDT_ERR_UNSUPPORTED_PARAMETER;
    }
}

/******************************************************************************/
vs_fldt_ret_code_e
vs_fldt_init(const vs_mac_addr_t *gateway_mac){
    vs_fldt_ret_code_e fldt_ret_code;

    VS_LOG_DEBUG("[FLDT] Initialization");

    FLDT_CHECK(vs_fldt_init_server(gateway_mac, vs_fldt_add_filetype), "Unable to initialize FLDT's server service");

    vs_fldt_fw_init();

    VS_LOG_DEBUG("[FLDT] Successfully initialized");

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
void
vs_fldt_destroy(void){
    vs_fldt_destroy_server();
}