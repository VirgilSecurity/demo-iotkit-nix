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
#include <virgil/iot/update/update.h>
#include <fldt_implementation.h>
#include <global-hal.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>


/******************************************************************************/
static void
_make_fw_file_type(vs_fldt_file_type_t *file_type, const uint8_t *manufacture_id, const uint8_t *device_type) {
    vs_update_firmware_add_data_t *fw_add_data = (vs_update_firmware_add_data_t *) file_type->add_info;

    memcpy(fw_add_data->manufacture_id, manufacture_id, sizeof(fw_add_data->manufacture_id));
    memcpy(fw_add_data->device_type, device_type, sizeof(fw_add_data->device_type));
    file_type->file_type_id = VS_UPDATE_FIRMWARE;
}

/******************************************************************************/
static void
_fill_ver(vs_fldt_file_version_t *dst, const vs_firmware_info_t *src){
    const vs_firmware_version_t *ver = NULL;

    assert(src);
    assert(dst);

    memset(dst, 0, sizeof(*dst));

    ver = &src->version;

    dst->major = ver->major;
    dst->minor = ver->minor;
    dst->patch = ver->patch;
    dst->dev_milestone = ver->dev_milestone;
    dst->dev_build = ver->dev_build;
    dst->timestamp = ver->timestamp;

    _make_fw_file_type(&dst->file_type, src->manufacture_id, src->device_type);

}

/******************************************************************************/
static vs_fldt_ret_code_e
get_version(void **storage_context,
            const vs_fldt_gfti_fileinfo_request_t *request,
            vs_fldt_gfti_fileinfo_response_t *response){
    const vs_firmware_descriptor_t *fw_descr = (const vs_firmware_descriptor_t *) *storage_context;
    char file_descr[FLDT_FILEVER_BUF];

    assert(storage_context);
    assert(request);
    assert(response);

    VS_LOG_DEBUG("[FLDT:get_version] ==> Get version for file version %s", vs_fldt_file_version_descr(file_descr, &response->version));

    memset(response, 0, sizeof(*response));

    memcpy(&response->gateway_mac, &vs_fldt_gateway_mac, sizeof(vs_fldt_gateway_mac));
    _fill_ver(&response->version, &fw_descr->info);

    VS_LOG_DEBUG("[FLDT:get_version] <== Send version : gateway MAC %02X:%02X:%02X:%02X:%02X:%02X, file version %s",
                 vs_fldt_gateway_mac.bytes[0],vs_fldt_gateway_mac.bytes[1],vs_fldt_gateway_mac.bytes[2],vs_fldt_gateway_mac.bytes[3],vs_fldt_gateway_mac.bytes[4],vs_fldt_gateway_mac.bytes[5],
                 vs_fldt_file_version_descr(file_descr, &response->version));

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
static vs_fldt_ret_code_e
get_header(void **storage_context,
           const vs_fldt_gnfh_header_request_t *request,
           uint16_t response_buf_sz,
           vs_fldt_gnfh_header_response_t *response){
    const vs_firmware_descriptor_t *fw_descr = (const vs_firmware_descriptor_t *) *storage_context;
    size_t fw_header_size;
    char file_descr[FLDT_FILEVER_BUF];

    assert(storage_context);
    assert(request);
    assert(response_buf_sz);
    assert(response);

    fw_header_size = sizeof(*fw_descr);

    VS_LOG_DEBUG("[FLDT:get_header] ==> Get header for file version %s",
            vs_fldt_file_version_descr(file_descr, &request->version));

    CHECK_RET(response_buf_sz >= fw_header_size, VS_FLDT_ERR_INCORRECT_ARGUMENT,
            "Response's buffer size %d is not enough to store firmware descriptor. Increase header_buf_size to fill vs_fldt_gnfh_header_response_t",
            response_buf_sz, fw_header_size);

    _fill_ver(&response->version, &fw_descr->info);
    response->header_size = fw_header_size;
    memcpy(response->header_data, fw_descr, fw_header_size);

    VS_LOG_DEBUG("[FLDT:get_header] <== Send header : padding = %d, chunk_size = %d, firmware_length = %d, app_size = %d",
                 fw_descr->padding, fw_descr->chunk_size, fw_descr->firmware_length, fw_descr->app_size);

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
static vs_fldt_ret_code_e
get_chunk(void **storage_context,
          const vs_fldt_gnfc_chunk_request_t *request,
          uint16_t response_buf_sz,
          vs_fldt_gnfc_chunk_response_t *response){
    vs_firmware_descriptor_t *fw_descr = (vs_firmware_descriptor_t *) *storage_context;
    char file_descr[FLDT_FILEVER_BUF];
    uint16_t data_sz = 0;
    uint32_t offset = 0;
    int update_ret_code;

    assert(storage_context);
    assert(request);
    assert(response_buf_sz);
    assert(response);

    VS_LOG_DEBUG("[FLDT:get_chunk] ==> Get chunk %d for file : %s",
                 request->chunk_id, vs_fldt_file_version_descr(file_descr, &request->version));

    _fill_ver(&response->version, &fw_descr->info);
    response->chunk_id = request->chunk_id;

    data_sz = VS_UPDATE_FIRMWARE_CHUNK_SIZE;
    offset = VS_UPDATE_FIRMWARE_CHUNK_SIZE * request->chunk_id;

    UPDATE_CHECK(vs_update_load_firmware_chunk(fw_descr,
                                  offset,
                                  response->chunk_data,
                                  data_sz,
                                  &data_sz),
    "Unable to get firmware chunk %d (offset %lu) for file version %s",
              request->chunk_id, offset, vs_fldt_file_version_descr(file_descr, &request->version));

    response->chunk_size = data_sz;

    VS_LOG_DEBUG("[FLDT:get_chunk] <== Send chunk %d (offset %d), %d bytes size", response->chunk_id, offset, data_sz);

    return VS_FLDT_ERR_OK;

}

/******************************************************************************/
static vs_fldt_ret_code_e
get_footer(void **storage_context,
           const vs_fldt_gnff_footer_request_t *request,
           uint16_t response_buf_sz,
           vs_fldt_gnff_footer_response_t *response){
    vs_firmware_descriptor_t *fw_descr = (vs_firmware_descriptor_t *) *storage_context;
    char file_descr[FLDT_FILEVER_BUF];
    uint16_t data_sz = 0;
    int update_ret_code;

    assert(storage_context);
    assert(request);
    assert(response_buf_sz);
    assert(response);

    VS_LOG_DEBUG("[FLDT:get_footer] ==> Get footer for file version %s", vs_fldt_file_version_descr(file_descr, &request->version));

    _fill_ver(&response->version, &fw_descr->info);

    data_sz = fw_descr->chunk_size;

    UPDATE_CHECK(vs_update_load_firmware_footer(fw_descr,
                                            response->footer_data,
                                            data_sz,
                                            &data_sz),
              "Unable to get firmware footer for file version %s",
              vs_fldt_file_version_descr(file_descr, &request->version));

    response->footer_size = data_sz;

    VS_LOG_DEBUG("[FLDT:get_footer] <== Send footer for file version %s, %d bytes size", vs_fldt_file_version_descr(file_descr, &response->version), data_sz);

    return VS_FLDT_ERR_OK;

}

/******************************************************************************/
static void
destroy(void **storage_context){
    free(*storage_context);
    *storage_context = NULL;
}

/******************************************************************************/
static vs_fldt_ret_code_e
_prepare_storage_context(vs_firmware_info_t *firmware_info, vs_firmware_descriptor_t *fw_descript){
    CHECK_NOT_ZERO_RET(firmware_info, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(fw_descript, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    int update_ret_code;

    memset(fw_descript, 0, sizeof(*fw_descript));

    UPDATE_CHECK(vs_update_load_firmware_descriptor(firmware_info->manufacture_id, firmware_info->device_type, fw_descript),
            "Unable to load firmware descriptor");

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
static vs_fldt_ret_code_e
_set_file_mapping_callback(vs_firmware_descriptor_t *fw_descript, vs_fldt_server_file_type_mapping_t *file_mapping){

    CHECK_NOT_ZERO_RET(fw_descript, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_mapping, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    file_mapping->storage_context = fw_descript;
    file_mapping->get_version = get_version;
    file_mapping->get_header = get_header;
    file_mapping->get_chunk = get_chunk;
    file_mapping->get_footer = get_footer;
    file_mapping->destroy = destroy;

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
static vs_fldt_ret_code_e
_prepare_file_mapping(vs_firmware_info_t *firmware_info, vs_firmware_descriptor_t *fw_descript, vs_fldt_server_file_type_mapping_t *file_mapping){
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(firmware_info, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(fw_descript, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(file_mapping, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    memset(file_mapping, 0, sizeof(*file_mapping));

    _make_fw_file_type(&file_mapping->file_type, firmware_info->manufacture_id, firmware_info->device_type);

    FLDT_CHECK(_set_file_mapping_callback(fw_descript, file_mapping), "Unable to prepare file mapping");

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
static vs_fldt_ret_code_e
_prepare_new_file_request(vs_firmware_info_t *firmware_info, vs_firmware_descriptor_t *fw_descript, vs_fldt_infv_new_file_request_t *new_file_request){

    CHECK_NOT_ZERO_RET(firmware_info, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(fw_descript, VS_FLDT_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(new_file_request, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    memset(new_file_request, 0, sizeof(*new_file_request));

    memcpy(&new_file_request->gateway_mac, &vs_fldt_gateway_mac, sizeof(vs_fldt_gateway_mac));

    _fill_ver(&new_file_request->version, firmware_info);

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
vs_fldt_ret_code_e
vs_fldt_add_fw_filetype(const vs_fldt_file_type_t *file_type){
    vs_firmware_descriptor_t *fw_descript;
    vs_fldt_server_file_type_mapping_t file_mapping;
    vs_fldt_ret_code_e fldt_ret_code;
    int update_ret_code;
    vs_update_firmware_add_data_t *fw_add_data = (vs_update_firmware_add_data_t *) file_type->add_info;

    assert(file_type);

    CHECK_RET(fw_descript = malloc(sizeof(*fw_descript)), VS_FLDT_ERR_NO_MEMORY, "Unable to allocate memory for firmware descriptor");
    memset(fw_descript, 0, sizeof(*fw_descript));

    UPDATE_CHECK(vs_update_load_firmware_descriptor(fw_add_data->manufacture_id, fw_add_data->device_type, fw_descript),
                 "Unable to load firmware descriptor");

    memcpy(&file_mapping.file_type, file_type, sizeof(*file_type));
    FLDT_CHECK(_set_file_mapping_callback(fw_descript, &file_mapping), "Unable to prepare file mapping");

    FLDT_CHECK(vs_fldt_update_server_file_type(&file_mapping), "Unable to update firmware file mapping");

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
int
vs_fldt_new_firmware_available(vs_firmware_info_t *firmware_info){
    vs_firmware_descriptor_t *fw_descript = NULL;
    vs_fldt_server_file_type_mapping_t file_mapping;
    vs_fldt_infv_new_file_request_t new_file_request;
    vs_fldt_ret_code_e fldt_ret_code;

    CHECK_NOT_ZERO_RET(firmware_info, VS_FLDT_ERR_INCORRECT_ARGUMENT);

    CHECK_RET(fw_descript = malloc(sizeof(*fw_descript)), VS_FLDT_ERR_NO_MEMORY, "Unable to allocate memory for firmware descriptor");

    FLDT_CHECK(_prepare_storage_context(firmware_info, fw_descript), "Unable to prepare storage context");

    FLDT_CHECK(_prepare_file_mapping(firmware_info, fw_descript, &file_mapping), "Unable to prepare storage context");

    FLDT_CHECK(vs_fldt_update_server_file_type(&file_mapping), "Unable to update firmware file mapping");

    FLDT_CHECK(_prepare_new_file_request(firmware_info, fw_descript, &new_file_request), "Unable to prepare storage context");

    FLDT_CHECK(vs_fldt_broadcast_new_file(&new_file_request), "Unable to process new firmware");

    return VS_FLDT_ERR_OK;
}