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

typedef struct resp_buff_s {
    uint8_t *buff;
    size_t buff_sz;
    size_t used_size;
} resp_buff_t;

/******************************************************************************/
static size_t
write_callback(char *contents, size_t size, size_t nmemb, void *userdata) {
    size_t chunksize = size * nmemb;
    resp_buff_t *resp = (resp_buff_t *)userdata;

    if (NULL == resp->buff || resp->used_size + chunksize > resp->buff_sz) {
        return 0;
    }
    memcpy(&(resp->buff[resp->used_size]), contents, chunksize);
    resp->used_size += chunksize;
    return chunksize;
}

/******************************************************************************/
uint16_t
https(http_method_t type,
      const char *url,
      const char *authorization,
      const char *data,
      size_t data_size,
      char *out_data,
      size_t *in_out_size) {
    CURL *curl;
    CURLcode curl_res;
    uint16_t res = HTTPS_RET_CODE_OK;
    resp_buff_t resp = {(uint8_t *)out_data, *in_out_size, 0};

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        switch (type) {
        case HTTP_GET:
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
