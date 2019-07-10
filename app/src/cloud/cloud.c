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
 * @file cloud.c
 * @brief Cloud service API.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "FreeRTOS.h"
#include "gateway.h"
#include "gateway_macro.h"
#include "cloud.h"
#include "https.h"
#include "base64/base64.h"
#include "json/json_generator.h"
#include "json/json_parser.h"

#include "crypto/asn1_cryptogram.h"
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/logger/logger.h>

#define MAX_EP_SIZE (256)

/******************************************************************************/
static bool
data_to_hex(const uint8_t *_data, uint32_t _len, uint8_t *_out_data, uint32_t *_in_out_len) {
    const uint8_t hex_str[] = "0123456789abcdef";

    if (!_len) {
        return false;
    }

    if (*_in_out_len < _len * 2 + 1) {
        return false;
    }

    *_in_out_len = _len * 2 + 1;
    _out_data[*_in_out_len - 1] = 0;
    size_t i;

    for (i = 0; i < _len; i++) {
        _out_data[i * 2 + 0] = hex_str[(_data[i] >> 4) & 0x0F];
        _out_data[i * 2 + 1] = hex_str[(_data[i]) & 0x0F];
    }
    return true;
}

/******************************************************************************/
static void
_get_serial_number_in_hex_str(char _out_str[SERIAL_SIZE * 2 + 1]) {
    uint32_t _in_out_len = SERIAL_SIZE * 2 + 1;
    uint8_t *serial_number = get_gateway_ctx()->udid_of_device;
    data_to_hex(serial_number, SERIAL_SIZE, (uint8_t *)_out_str, &_in_out_len);
}

/******************************************************************************/
uint8_t
remove_padding_size(uint8_t * data, size_t data_sz) {
    uint8_t i, padding_val;

    padding_val = data[data_sz - 1];

    if (padding_val < 2 || padding_val > 15 || data_sz < padding_val) return 0;

    for (i = 0; i < padding_val; ++i) {
        if (data[data_sz - 1 - i] != padding_val) {
            return 0;
        }
    }

    return padding_val;
}

#define ATCA_SHA384_DIGEST_SIZE 48
#define KDF2_CEIL(x,y) (1 + ((x - 1) / y))
#define MAX_KDF_IN 100
/******************************************************************************/
//bool
//_kdf2_sha384(const uint8_t *  input, size_t inlen, uint8_t * output, size_t olen) {
//    size_t counter = 1;
//    size_t counter_len;
//    uint8_t buf[MAX_KDF_IN + 5];
//    uint8_t hash[ATCA_SHA384_DIGEST_SIZE];
//    uint8_t hash_len = ATCA_SHA384_DIGEST_SIZE;
//    size_t olen_actual = 0;
//    uint8_t counter_string[4];
//    uint16_t hash_sz;
//
//    // Get KDF parameters
//    counter_len = KDF2_CEIL(olen, hash_len);
//
//    // Start hashing
//    for(; counter <= counter_len; ++counter) {
//        counter_string[0] = (uint8_t)((counter >> 24) & 255);
//        counter_string[1] = (uint8_t)((counter >> 16) & 255);
//        counter_string[2] = (uint8_t)((counter >> 8)) & 255;
//        counter_string[3] = (uint8_t)(counter & 255);
//
//        memcpy(buf, input, inlen);
//        memcpy(&buf[inlen], counter_string, 4);
//
//        if (olen_actual + hash_len <= olen) {
//            vs_hsm_hash_create(VS_HASH_SHA_384, (const unsigned char *)buf,inlen + 4, (unsigned char *)(output + olen_actual), olen, &hash_sz);
//            olen_actual += hash_len;
//        } else {
//            vs_hsm_hash_create(VS_HASH_SHA_384, (const unsigned char *)buf,inlen + 4, (unsigned char *)hash, sizeof(hash), &hash_sz);
//            memcpy(output + olen_actual, hash, olen - olen_actual);
//            olen_actual = olen;
//        }
//    }
//
//    return true;
//}

/******************************************************************************/
static bool
_crypto_decrypt_sha384_aes256(const uint8_t *recipient_id,
                              size_t recipient_id_sz,
                              const uint8_t *private_key,
                              size_t private_key_sz,
                              uint8_t *cryptogram,
                              size_t cryptogram_sz,
                              uint8_t *decrypted_data,
                              size_t buf_sz,
                              size_t *decrypted_data_sz) {
    uint8_t decrypted_key[48];
    uint8_t * encrypted_data;
    size_t encrypted_data_sz;

//    uint8_t pre_master_key[32];
//    uint8_t master_key[80];

    uint8_t * public_key;
    uint8_t * iv_key;
    uint8_t * encrypted_key;
    uint8_t * mac_data;
    uint8_t * iv_data;

    if (!virgil_cryptogram_parse_low_level_sha384_aes256(cryptogram, cryptogram_sz,
                                                         recipient_id, recipient_id_sz,
                                                         &public_key,
                                                         &iv_key,
                                                         &encrypted_key,
                                                         &mac_data,
                                                         &iv_data,
                                                         &encrypted_data,
                                                         &encrypted_data_sz)) {
        return false;
    }

//    if (!_dh(public_key, pre_master_key)
//        || !_kdf2_sha384(pre_master_key,
//                                  32,
//                                  master_key,
//                                  sizeof(master_key))) {
//        return false;
//    }

    memcpy(decrypted_key, encrypted_key, 48);
//    aes256_cbc_decrypt(master_key,
//                       iv_key,
//                       decrypted_key,
//                       48);

    if (buf_sz < encrypted_data_sz) {
        return false;
    }

    *decrypted_data_sz = encrypted_data_sz - 16;

//    aes256_gcm_ad(decrypted_key,
//                  iv_data,
//                  encrypted_data,
//                  encrypted_data_sz - 16,
//                  decrypted_data,
//                  &encrypted_data[encrypted_data_sz - 16]);

    *decrypted_data_sz -= remove_padding_size(decrypted_data, *decrypted_data_sz);

    return true;
}

/******************************************************************************/
static int16_t
_decrypt_answer(char *out_answer, size_t *in_out_answer_len) {
    jobj_t jobj;
    size_t buf_size = *in_out_answer_len;

    if (json_parse_start(&jobj, out_answer, buf_size) != GATEWAY_OK)
        return CLOUD_ANSWER_JSON_FAIL;

    char *crypto_answer_b64 = (char *)pvPortMalloc(buf_size);

    int crypto_answer_b64_len;

    if (json_get_val_str(&jobj, "encrypted_value", crypto_answer_b64, (int)buf_size) != GATEWAY_OK)
        return CLOUD_VALUE_ANSWER_JSON_FAIL;
    else {
        crypto_answer_b64_len = base64decode_len(crypto_answer_b64, (int)strlen(crypto_answer_b64));

        if (0 >= crypto_answer_b64_len || crypto_answer_b64_len > buf_size) {
            goto fail;
        }

        base64decode(crypto_answer_b64,
                     (int)strlen(crypto_answer_b64),
                     (uint8_t *)crypto_answer_b64,
                     &crypto_answer_b64_len);
        size_t decrypted_data_sz;

        if (!_crypto_decrypt_sha384_aes256(0,
                                           0,
                                           NULL,
                                           0,
                                           (uint8_t *)crypto_answer_b64,
                                           (size_t)crypto_answer_b64_len,
                                           (uint8_t *)out_answer,
                                           buf_size,
                                           &decrypted_data_sz) ||
            decrypted_data_sz > UINT16_MAX) {
            goto fail;
        }
        *in_out_answer_len = (uint16_t)decrypted_data_sz;
        out_answer[*in_out_answer_len] = '\0';
    }
    vPortFree(crypto_answer_b64);
    return HTTPS_RET_CODE_OK;

fail:
    vPortFree(crypto_answer_b64);
    *in_out_answer_len = 0;
    out_answer[0] = '\0';
    return CLOUD_DECRYPT_ANSWER_JSON_FAIL;
}

/******************************************************************************/
int16_t
cloud_get_gateway_iot(char *out_answer, size_t *in_out_answer_len) {
    int16_t ret;
    char *url = (char *)pvPortMalloc(512);

    char serial[SERIAL_SIZE * 2 + 1];
    _get_serial_number_in_hex_str(serial);

    int res = snprintf(url, MAX_EP_SIZE, "%s/%s/%s/%s", CLOUD_HOST, THING_EP, serial, AWS_ID);
    if (res < 0 || res > MAX_EP_SIZE ||
        https(HTTP_GET, url, NULL, NULL, 0, out_answer, in_out_answer_len) != HTTPS_RET_CODE_OK) {
        ret = CLOUD_FAIL;
    } else {
        ret = _decrypt_answer(out_answer, in_out_answer_len);
    }

    vPortFree(url);
    return ret;
}

/******************************************************************************/
int16_t
cloud_get_message_bin_credentials(char *out_answer, size_t *in_out_answer_len) {
    int16_t ret;
    char *url = (char *)pvPortMalloc(MAX_EP_SIZE);

    char serial[SERIAL_SIZE * 2 + 1];
    _get_serial_number_in_hex_str(serial);

    int res = snprintf(url, MAX_EP_SIZE, "%s/%s/%s/%s", CLOUD_HOST, THING_EP, serial, MQTT_ID);

    if (res < 0 || res > MAX_EP_SIZE ||
        https(HTTP_GET, url, NULL, NULL, 0, out_answer, in_out_answer_len) != HTTPS_RET_CODE_OK) {
        ret = CLOUD_FAIL;
    } else {
        ret = _decrypt_answer(out_answer, in_out_answer_len);
    }

    vPortFree(url);
    return ret;
}
