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
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <fldt_implementation.h>

// TODO : just for now
typedef struct{
    uint8_t *buf;
    vs_fldt_infv_new_file_request_t file_ver;
    vs_fldt_gnfh_header_response_t *header;
    uint8_t *file_data;
    vs_fldt_gnff_footer_response_t *footer;
} vs_fldt_file_t;

static vs_fldt_file_t _file[VS_FLDT_FILETYPES_AMOUNT];
static bool _initialized = false;

/******************************************************************************/
// Get File Version
static int
_get_version_callback(const vs_fldt_gfti_fileinfo_request_t *request, vs_fldt_gfti_fileinfo_response_t *response){
    const vs_fldt_file_type_t *file_type = NULL;
    uint8_t file_type_id;
    const vs_fldt_infv_new_file_request_t *file_ver_request;
    char file_ver_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(response, -2);

    file_type = &request->file_type;
    file_type_id = file_type->file_type;

    CHECK_RET(file_type_id > 0 && file_type_id < VS_FLDT_FILETYPES_AMOUNT, -3, "Unsupported file type %d", file_type_id);

    file_ver_request = &_file[file_type_id].file_ver;
    memcpy(response, file_ver_request, sizeof(*response));

    VS_LOG_DEBUG("[FLDT:get_version] Get version for file type %s : %s", vs_fldt_file_type_descr(file_type), vs_fldt_file_version_descr(file_ver_descr, &file_ver_request->version));

    return 0;
}

/******************************************************************************/
// Get File Header
static int
_get_header_callback(const vs_fldt_gnfh_header_request_t *request, uint16_t response_buf_sz, vs_fldt_gnfh_header_response_t *response){
    const vs_fldt_file_version_t *file_version = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_gnfh_header_response_t *header = NULL;
    uint8_t file_type_id;
    size_t response_sz;
    char file_ver_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(response, -2);

    file_version = &request->version;
    file_type = &file_version->file_type;
    file_type_id = file_type->file_type;

    CHECK_RET(file_type_id > 0 && file_type_id < VS_FLDT_FILETYPES_AMOUNT, -3, "Unsupported file type %d", file_type_id);

    header = _file[file_type_id].header;
    response_sz = sizeof(*header) + header->header_size;

    VS_LOG_DEBUG("[FLDT:get_header] Get header for file %s. Header : %d bytes data, chunks : %d x %d bytes, footer : %d bytes data",
            vs_fldt_file_version_descr(file_ver_descr, file_version),
            header->header_size, header->chunks_amount, header->chunk_size, header->footer_size);

    CHECK_RET(response_buf_sz >= response_sz, -4, "Response buffer size %d provided by client is lower than needed size %d", (int) response_buf_sz, (int) response_sz);

    memcpy(response, header, response_sz);

    return 0;
}

/******************************************************************************/
// Get File Chunk
static int
_get_chunk_callback(const vs_fldt_gnfc_chunk_request_t *request, uint16_t response_buf_sz, vs_fldt_gnfc_chunk_response_t *response){
    const vs_fldt_file_version_t *file_version = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_gnfh_header_response_t *header = NULL;
    const uint8_t *data = NULL;
    uint8_t file_type_id = -1;
    size_t chunk_id = -1;
    size_t chunk_sz = 0;
    size_t response_off = 0;
    size_t response_size = 0;
    char file_ver_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(response, -2);

    file_version = &request->version;
    file_type = &file_version->file_type;
    file_type_id = file_type->file_type;
    chunk_id = request->chunk_id;

    CHECK_RET(file_type_id > 0 && file_type_id < VS_FLDT_FILETYPES_AMOUNT, -3, "Unsupported file type %d", file_type_id);

    header = _file[file_type_id].header;
    if(chunk_id < header->chunks_amount){
        chunk_sz = header->chunk_size;
        response_off = chunk_id * chunk_sz;
        data = _file[file_type_id].file_data + response_off;
    }

    response_size = sizeof(*response) + chunk_sz;

    VS_LOG_DEBUG("[FLDT:get_chunk] Get chunk %d (%d bytes) for file %s", chunk_id, chunk_sz, vs_fldt_file_version_descr(file_ver_descr, file_version));

    CHECK_RET(chunk_id < header->chunks_amount, -4, "Chunk id %d is bigger than chunks amount %d", request->chunk_id, header->chunks_amount);
    CHECK_RET(response_buf_sz >= response_size, -5, "Response data buffer size %d provided by client is lower than data size %d", (int) response_buf_sz, (int) response_size);

    if(data) {
        response->chunk_id = chunk_id;
        response->chunk_size = chunk_sz;
        memcpy(&response->version, &_file[file_type_id].file_ver, sizeof(response->version));
        memcpy(response->chunk_data, data, chunk_sz);
    }

    return 0;
}

/******************************************************************************/
// Get File Footer
static int
_get_footer_callback(const vs_fldt_gnff_footer_request_t *request, uint16_t response_buf_sz, vs_fldt_gnff_footer_response_t *response){
    const vs_fldt_file_version_t *file_version = NULL;
    const vs_fldt_file_type_t *file_type = NULL;
    const vs_fldt_gnfh_header_response_t *header = NULL;
    const vs_fldt_gnff_footer_response_t *footer = NULL;
    uint8_t file_type_id;
    size_t response_sz;
    char file_ver_descr[FLDT_FILEVER_BUF];

    CHECK_NOT_ZERO_RET(request, -1);
    CHECK_NOT_ZERO_RET(response, -2);

    file_version = &request->version;
    file_type = &file_version->file_type;
    file_type_id = file_type->file_type;

    CHECK_RET(file_type_id > 0 && file_type_id < VS_FLDT_FILETYPES_AMOUNT, -3, "Unsupported file type %d", file_type_id);

    header = _file[file_type_id].header;
    footer = _file[file_type_id].footer;
    response_sz = sizeof(*footer) + header->footer_size;

    VS_LOG_DEBUG("[FLDT:get_footer] Get footer (%d bytes data) for file %s", header->footer_size, vs_fldt_file_version_descr(file_ver_descr, file_version));

    CHECK_RET(header->footer_size > 0, -4, "There is no footer for this file");
    CHECK_RET(response_buf_sz >= response_sz, -5, "Response buffer size %d provided by client is lower than needed size %d", (int) response_buf_sz, (int) response_sz);

    memcpy(response, footer, response_sz);

    return 0;
}

/******************************************************************************/
int
vs_fldt_init(void){
    vs_fldt_server_file_type_mapping_t file_map;
    size_t id;

    if(_initialized){
        assert(false && "It is already initialized. Ambiguous call");
        return 0;
    }

    VS_LOG_DEBUG("[FLDT] Initialization");

    file_map.get_version = _get_version_callback;
    file_map.get_header = _get_header_callback;
    file_map.get_chunk = _get_chunk_callback;
    file_map.get_footer = _get_footer_callback;

    for(id = 0; id < VS_FLDT_FILETYPES_AMOUNT; ++id) {

        memset(&_file[id], 0, sizeof(_file[id]));

        file_map.file_type.file_type = id;
        CHECK_RET(!vs_fldt_add_server_file_type(&file_map), -1, "Unable to register FLDT file type callback map element");
    }

    vs_fldt_set_is_gateway(true);

    VS_LOG_DEBUG("[FLDT] Successfully initialized");

    _initialized = true;

    return 0;
}

/******************************************************************************/
int
vs_fldt_new_file_available(const vs_fldt_infv_new_file_request_t *file_ver,
        const vs_fldt_gnfh_header_response_t *header,
        const vs_fldt_gnff_footer_response_t *footer,
        const uint8_t *data){
    uint8_t file_type;
    vs_fldt_file_t *file;
    char file_ver_descr[FLDT_FILEVER_BUF];
    size_t header_off;
    size_t header_sz;
    size_t file_data_off;
    size_t file_data_sz;
    size_t footer_off;
    size_t footer_sz;

    VS_LOG_DEBUG("[FLDT] New file is available. %s", vs_fldt_file_version_descr(file_ver_descr, &file_ver->version));

    CHECK_NOT_ZERO_RET(file_ver, -1);
    CHECK_NOT_ZERO_RET(header, -2);

    file_type = file_ver->version.file_type.file_type;

    CHECK_RET(file_type >= 0 && file_type < VS_FLDT_FILETYPES_AMOUNT, -3, "Unsupported file type");

    CHECK_RET(_initialized, -4, "FLDT has not been initialized");

    file = &_file[file_type];
    memcpy(&file->file_ver, file_ver, sizeof(*file_ver));

    header_off = 0;
    header_sz = sizeof(vs_fldt_gnfh_header_response_t) + header->header_size;

    file_data_off = header_off + header_sz;
    file_data_sz = header->chunk_size * header->chunks_amount;

    footer_off = file_data_off + file_data_sz;
    if(footer) {
        footer_sz = sizeof(*footer) + footer->footer_size;
    } else {
        footer_sz = 0;
    }

    file->buf = calloc(1, header_sz + file_data_sz + footer_sz);

    file->header = (vs_fldt_gnfh_header_response_t *) (file->buf + header_off);
    memcpy(file->header, header, header_sz);

    file->file_data = file->buf + file_data_off;
    memcpy(file->file_data, data, file_data_sz);

    if(footer != NULL){
        file->footer = (vs_fldt_gnff_footer_response_t *)(file->buf + footer_off);
        memcpy(file->footer, footer, footer_sz);
    } else {
        file->footer = NULL;
    }

    CHECK_RET(!vs_fldt_broadcast_new_file(file_ver),
            -5,
            "Unable to broadcast \"Is New File Version\" for file %s",
            vs_fldt_file_version_descr(file_ver_descr, &file_ver->version));

    return 0;
}
