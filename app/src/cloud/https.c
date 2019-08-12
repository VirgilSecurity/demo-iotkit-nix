/**
 * Copyright (C) 2017 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file https.c
 * @brief https wrapper.
 */

#include <virgil/iot/cloud/cloud.h>
#include <string.h>
#include <curl/curl.h>

#if !SIMULATOR || !SIM_FETCH_FIRMWARE

typedef struct resp_buff_s {
    uint8_t *buff;
    size_t buff_sz;
    size_t used_size;
    vs_fetch_handler_func_t fetch_handler;
    void *userdata;
} resp_buff_t;

/******************************************************************************/
static size_t
write_callback(char *contents, size_t size, size_t nmemb, void *userdata) {
    resp_buff_t *resp = (resp_buff_t *)userdata;
    size_t chunksize = size * nmemb;

    if (resp->fetch_handler) {
        return resp->fetch_handler(contents, chunksize, resp->userdata);
    }

    if (NULL == resp->buff || resp->used_size + chunksize > resp->buff_sz) {
        return 0;
    }
    memcpy(&(resp->buff[resp->used_size]), contents, chunksize);
    resp->used_size += chunksize;
    return chunksize;
}

/******************************************************************************/
uint16_t
vs_cloud_https_hal(vs_http_method_t type,
                   const char *url,
                   const char *data,
                   size_t data_size,
                   char *out_data,
                   vs_fetch_handler_func_t fetch_handler,
                   void *hander_data,
                   size_t *in_out_size) {
    CURL *curl;
    CURLcode curl_res;
    uint16_t res = HTTPS_RET_CODE_OK;

    if (NULL == in_out_size) {
        return HTTPS_RET_CODE_ERROR_PREPARE_REQ;
    }

    resp_buff_t resp = {(uint8_t *)out_data, *in_out_size, 0, fetch_handler, hander_data};

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        switch (type) {
        case VS_HTTP_GET:
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
            curl_easy_setopt(curl, CURLOPT_HEADER, 0L);

            break;
        default:
            res = HTTPS_RET_CODE_ERROR_PREPARE_REQ;
            goto cleanup;
        }

        curl_res = curl_easy_perform(curl);

        if (CURLE_OK != curl_res) {
            res = HTTPS_RET_CODE_ERROR_SEND_REQ;
        }
        *in_out_size = resp.used_size;
    }

cleanup:
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return res;
}
#else

#include "hal/file_io_hal.h"
#include "gateway.h"
#include <stdlib-config.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>

uint16_t
vs_cloud_https_hal(vs_http_method_t type,
                   const char *url,
                   const char *data,
                   size_t data_size,
                   char *out_data,
                   vs_fetch_handler_func_t fetch_handler,
                   void *hander_data,
                   size_t *in_out_size) {

    int file_sz;
    uint16_t buf_sz;
    uint8_t *file_buf = NULL;

    CHECK_NOT_ZERO_RET(in_out_size, HTTPS_RET_CODE_ERROR_PREPARE_REQ);
    CHECK_NOT_ZERO_RET(fetch_handler, HTTPS_RET_CODE_ERROR_PREPARE_REQ);

    file_sz = vs_gateway_get_file_len(vs_gateway_get_sim_fw_images_dir(), firmware_name);

    CHECK_RET(file_sz > 0, HTTPS_RET_CODE_ERROR_PREPARE_REQ, "Error firmware file size")

    buf_sz = file_sz > UINT16_MAX ? UINT16_MAX : file_sz;

    file_buf = VS_IOT_MALLOC(file_sz);
    CHECK_NOT_ZERO_RET(file_buf, HTTPS_RET_CODE_ERROR_PREPARE_REQ);

    uint32_t offset = 0;
    while (offset < file_sz) {
        uint16_t read_sz;
        uint16_t required_sz = file_sz - offset > buf_sz ? buf_sz : file_sz - offset;
        if (!vs_gateway_read_file_data(
                    vs_gateway_get_sim_fw_images_dir(), firmware_name, offset, file_buf, required_sz, &read_sz) ||
            required_sz != fetch_handler((char *)file_buf, required_sz, hander_data)) {
            VS_IOT_FREE(file_buf);
            return HTTPS_RET_CODE_ERROR_GET;
        }

        offset += required_sz;
    }


    VS_IOT_FREE(file_buf);
    return HTTPS_RET_CODE_OK;
}

#endif // SIM_FETCH_FIRMWARE