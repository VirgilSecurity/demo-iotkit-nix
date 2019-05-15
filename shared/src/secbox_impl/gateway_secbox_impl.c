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
#include <virgil/iot/secbox/secbox.h>

#include "gateway_macro.h"
#include "secbox_impl/file-system.h"
//#include <mbedtls/asn1.h>
//#include <mbedtls/asn1write.h>
//#include <mbedtls/oid.h>
//#include <virgil/crypto/common/private/vsc_buffer_defs.h>
//#include <virgil/crypto/foundation/vscf_hash.h>
//#include <virgil/crypto/foundation/vscf_impl.h>
//#include <virgil/crypto/foundation/vscf_key_provider.h>
//#include <virgil/crypto/foundation/vscf_private_key.h>
//#include <virgil/crypto/foundation/vscf_public_key.h>
//#include <virgil/crypto/foundation/vscf_sha256.h>
//#include <virgil/crypto/foundation/vscf_sign_hash.h>

// static int
// vs_secbox_gateway_load(vs_secbox_element_info_t* element_info, uint8_t* out_data, size_t buf_sz, size_t* out_sz);
// static int
// vs_secbox_gateway_save(vs_secbox_element_info_t* element_info, const uint8_t* in_data, size_t data_sz);
// static int
// vs_secbox_gateway_del(vs_secbox_element_info_t* element_info);
// static int
// vs_secbox_gateway_sign_data(vs_secbox_sign_info_t* sign_info,
//    const uint8_t* data,
//    size_t data_sz,
//    uint8_t* signature,
//    size_t buf_sz,
//    size_t* signature_sz);
//
// static vs_secbox_hal_impl_t _secbox_gateway = { .save = vs_secbox_gateway_save,
//    .load = vs_secbox_gateway_load,
//    .del = vs_secbox_gateway_del,
//    .sign = vs_secbox_gateway_sign_data };

static vs_secbox_hal_impl_t _secbox_gateway = {.save = 0, .load = 0, .del = 0, .init = 0};

///******************************************************************************/
//#define ASN1_CHK_ADD(g, f)    \
//    do {                      \
//        if ((res_sz = f) < 0) \
//            return (false);   \
//        else                  \
//            g += res_sz;      \
//    } while (0)
//
// static bool
//_mbedtls_sign_to_virgil(uint8_t hash_type,
//    uint8_t* mbedtls_sign,
//    size_t mbedtls_sign_sz,
//    uint8_t* virgil_sign,
//    size_t buf_sz,
//    size_t* virgil_sign_sz)
//{
//    int res_sz;
//    unsigned char* buf = virgil_sign;
//    unsigned char* p = buf + buf_sz;
//    size_t len = 0;
//    size_t hash_type_len = 0;
//    const char* oid = 0;
//    size_t oid_len;
//
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, buf, mbedtls_sign, mbedtls_sign_sz));
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_OCTET_STRING));
//
//    ASN1_CHK_ADD(hash_type_len, mbedtls_asn1_write_null(&p, buf));
//
//    if (0 != mbedtls_oid_get_oid_by_md(hash_type, &oid, &oid_len))
//        return false;
//
//    ASN1_CHK_ADD(hash_type_len, mbedtls_asn1_write_oid(&p, buf, oid, oid_len));
//
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, hash_type_len));
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
//
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len + hash_type_len));
//    ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
//
//    len += hash_type_len;
//
//    if (buf_sz > len) {
//        memmove(virgil_sign, p, len);
//    }
//
//    *virgil_sign_sz = len;
//
//    return true;
//}
//
///******************************************************************************/
// static int
//_generate_own_keypair(size_t keypair_type, uint8_t* out_public_part_buf, size_t buf_sz, size_t* out_sz)
//{
//    int res = 0;
//    vscf_key_provider_t* key_provider = vscf_key_provider_new();
//    vscf_impl_t* privkey_ctx = NULL;
//    vsc_buffer_t* privkey_buffer = NULL;
//    vscf_impl_t* pubkey_ctx = NULL;
//    vsc_buffer_t* pubkey_buffer = NULL;
//    vscf_error_t error;
//
//    error.status = vscf_key_provider_setup_defaults(key_provider);
//    if (vscf_status_SUCCESS != error.status) {
//        res = -1;
//        goto cleanup;
//    }
//
//    privkey_ctx = vscf_key_provider_generate_private_key(key_provider, keypair_type, &error);
//    if (vscf_status_SUCCESS != error.status) {
//        res = -1;
//        goto cleanup;
//    }
//    privkey_buffer = vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider,
//    privkey_ctx)); error.status = vscf_key_provider_export_private_key(key_provider, privkey_ctx, privkey_buffer); if
//    (vscf_status_SUCCESS != error.status) {
//        res = -1;
//        goto cleanup;
//    }
//
//    // prepare folder
//    char folder[FILENAME_MAX];
//    prepare_keystorage_folder(folder);
//    if (!write_keystorage_file(
//            folder, OWN_PRIVATE_KEY_FILENAME, vsc_buffer_begin(privkey_buffer), vsc_buffer_len(privkey_buffer))) {
//        res = -1;
//        goto cleanup;
//    }
//
//    // Fill own public key
//    pubkey_buffer = vsc_buffer_new();
//    vsc_buffer_use(pubkey_buffer, out_public_part_buf, buf_sz);
//    pubkey_ctx = vscf_private_key_extract_public_key(privkey_ctx);
//    if (vscf_status_SUCCESS != vscf_public_key_export_public_key(pubkey_ctx, pubkey_buffer) ||
//    vsc_buffer_len(pubkey_buffer) > UINT8_MAX) {
//        res = -1;
//        goto cleanup;
//    }
//
//    *out_sz = (uint8_t)vsc_buffer_len(pubkey_buffer);
//
// cleanup:
//    vsc_buffer_delete(pubkey_buffer);
//    vsc_buffer_delete(privkey_buffer);
//    vscf_key_provider_delete(key_provider);
//    vscf_impl_delete(privkey_ctx);
//    vscf_impl_delete(pubkey_ctx);
//
//    return res;
//}
///******************************************************************************/
// static int
//_get_own_pubkey(vs_secbox_element_info_t* element_info, uint8_t* out_pubkey, size_t buf_sz, size_t* out_sz)
//{
//    // prepare folder
//    char folder[FILENAME_MAX];
//    uint8_t buf[2048];
//    prepare_keystorage_folder(folder);
//    size_t priv_key_sz;
//
//    if (!read_keystorage_file(folder, OWN_PRIVATE_KEY_FILENAME, buf, sizeof(buf), &priv_key_sz)) {
//        return _generate_own_keypair(element_info->index, out_pubkey, buf_sz, out_sz);
//    }
//
//    int res = 0;
//    vsc_data_t privkey_data = vsc_data(buf, priv_key_sz);
//    vscf_key_provider_t* key_provider = vscf_key_provider_new();
//    vscf_error_t error;
//    vscf_impl_t* privkey_ctx = NULL;
//    vscf_impl_t* pubkey_ctx = NULL;
//    vsc_buffer_t* pubkey_buffer = NULL;
//
//    error.status = vscf_key_provider_setup_defaults(key_provider);
//    if (vscf_status_SUCCESS != error.status) {
//        res = -1;
//        goto cleanup;
//    }
//
//    privkey_ctx = vscf_key_provider_import_private_key(key_provider, privkey_data, &error);
//    if (vscf_status_SUCCESS != error.status) {
//        res = -1;
//        goto cleanup;
//    }
//
//    // Fill own public key
//    pubkey_buffer = vsc_buffer_new();
//    vsc_buffer_use(pubkey_buffer, out_pubkey, buf_sz);
//    pubkey_ctx = vscf_private_key_extract_public_key(privkey_ctx);
//    if (vscf_status_SUCCESS != vscf_public_key_export_public_key(pubkey_ctx, pubkey_buffer)) {
//        res = -1;
//        goto cleanup;
//    }
//    *out_sz = vsc_buffer_len(pubkey_buffer);
//
// cleanup:
//    vsc_buffer_delete(pubkey_buffer);
//    vscf_key_provider_delete(key_provider);
//    vscf_impl_delete(privkey_ctx);
//    vscf_impl_delete(pubkey_ctx);
//
//    return res;
//}

/******************************************************************************/
// static int
// vs_secbox_gateway_save(vs_secbox_element_info_t* element_info, const uint8_t* in_data, size_t data_sz)
//{
//    assert(element_info);
//    assert(in_data);
//    if (element_info->id <= VS_SECBOX_ELEMENT_MIN || element_info->id >= VS_SECBOX_ELEMENT_MAX) {
//        return GATEWAY_ERROR;
//    }
//
//    int res = GATEWAY_ERROR;
//    // prepare folder
//    char folder[FILENAME_MAX];
//    char filename[FILENAME_MAX];
//    prepare_keystorage_folder(folder);
//
//    switch (element_info->id) {
//    case VS_SECBOX_ELEMENT_PBR:
//        if (data_sz == sizeof(crypto_signed_hl_public_key_t)) {
//            snprintf(filename, sizeof(filename), "%s_%zu", PBR_FILENAME_PREFIX, element_info->index);
//            res = write_keystorage_file(folder, filename, in_data, data_sz) ? GATEWAY_OK : GATEWAY_ERROR;
//        }
//        break;
//    case VS_SECBOX_ELEMENT_PBA:
//        if (data_sz == sizeof(crypto_signed_hl_public_key_t) && keystorage_verify_hl_key_sign(in_data, data_sz)) {
//            snprintf(filename, sizeof(filename), "%s_%zu", PBA_FILENAME_PREFIX, element_info->index);
//            res = write_keystorage_file(folder, filename, in_data, data_sz) ? GATEWAY_OK : GATEWAY_ERROR;
//        }
//        break;
//    case VS_SECBOX_ELEMENT_PBT:
//        if (data_sz == sizeof(crypto_signed_hl_public_key_t) && keystorage_verify_hl_key_sign(in_data, data_sz)) {
//            snprintf(filename, sizeof(filename), "%s_%zu", PBT_FILENAME_PREFIX, element_info->index);
//            res = write_keystorage_file(folder, filename, in_data, data_sz) ? GATEWAY_OK : GATEWAY_ERROR;
//        }
//        break;
//    case VS_SECBOX_ELEMENT_PBF:
//        if (data_sz == sizeof(crypto_signed_hl_public_key_t) && keystorage_verify_hl_key_sign(in_data, data_sz)) {
//            snprintf(filename, sizeof(filename), "%s_%zu", PBF_FILENAME_PREFIX, element_info->index);
//            res = write_keystorage_file(folder, filename, in_data, data_sz) ? GATEWAY_OK : GATEWAY_ERROR;
//        }
//        break;
//    case VS_SECBOX_ELEMENT_SGN:
//        res = write_keystorage_file(folder, SGN_FILENAME_PREFIX, in_data, data_sz) ? GATEWAY_OK : GATEWAY_ERROR;
//        break;
//    case VS_SECBOX_ELEMENT_TLH:
//        if (sizeof(trust_list_header_t) == data_sz) {
//            res = keystorage_save_tl_header(TL_STORAGE_TYPE_TMP, (trust_list_header_t*)in_data);
//        }
//        break;
//    case VS_SECBOX_ELEMENT_TLF:
//
//        if (sizeof(trust_list_footer_t) == data_sz) {
//            res = keystorage_save_tl_footer(TL_STORAGE_TYPE_TMP, (trust_list_footer_t*)in_data);
//
//            if (GATEWAY_OK == res) {
//                res = keystorage_apply_tmp_tl_to(TL_STORAGE_TYPE_STATIC);
//                if (GATEWAY_OK == res) {
//                    res = keystorage_apply_tmp_tl_to(TL_STORAGE_TYPE_DYNAMIC);
//                }
//            }
//        }
//        keystorage_invalidate_tl(TL_STORAGE_TYPE_TMP);
//        break;
//    case VS_SECBOX_ELEMENT_TLC:
//        if (sizeof(trust_list_pub_key_t) == data_sz) {
//            res = keystorage_save_tl_key(TL_STORAGE_TYPE_TMP, (trust_list_pub_key_t*)in_data);
//        }
//        break;
//    default:
//        break;
//    }
//
//    return res;
//}

/******************************************************************************/
// static int
// vs_secbox_gateway_load(vs_secbox_element_info_t* element_info, uint8_t* out_data, size_t buf_sz, size_t* out_sz)
//{
//    assert(element_info);
//    assert(out_data);
//    assert(out_sz);
//
//    if (element_info->id <= VS_SECBOX_ELEMENT_MIN || element_info->id >= VS_SECBOX_ELEMENT_MAX) {
//        return GATEWAY_ERROR;
//    }
//
//    // prepare folder
//    char folder[FILENAME_MAX];
//    char filename[FILENAME_MAX];
//    prepare_keystorage_folder(folder);
//
//    switch (element_info->id) {
//    case VS_SECBOX_ELEMENT_GET_OWN_PUBKEY:
//        return _get_own_pubkey(element_info, out_data, buf_sz, out_sz);
//    case VS_SECBOX_ELEMENT_PBR:
//        snprintf(filename, sizeof(filename), "%s_%zu", PBR_FILENAME_PREFIX, element_info->index);
//        break;
//    case VS_SECBOX_ELEMENT_PBA:
//        snprintf(filename, sizeof(filename), "%s_%zu", PBA_FILENAME_PREFIX, element_info->index);
//        break;
//    case VS_SECBOX_ELEMENT_PBT:
//        snprintf(filename, sizeof(filename), "%s_%zu", PBT_FILENAME_PREFIX, element_info->index);
//        break;
//    case VS_SECBOX_ELEMENT_PBF:
//        snprintf(filename, sizeof(filename), "%s_%zu", PBF_FILENAME_PREFIX, element_info->index);
//        break;
//    case VS_SECBOX_ELEMENT_SGN:
//        snprintf(filename, sizeof(filename), "%s", SGN_FILENAME_PREFIX);
//        break;
//    case VS_SECBOX_ELEMENT_TLH:
//        snprintf(filename, sizeof(filename), "%s", TL_HEADER_FILENAME_PREFIX);
//        break;
//    case VS_SECBOX_ELEMENT_TLF:
//        snprintf(filename, sizeof(filename), "%s", TL_FOOTER_FILENAME_PREFIX);
//        break;
//    case VS_SECBOX_ELEMENT_TLC:
//        snprintf(filename, sizeof(filename), "%s_%zu", TL_KEY_FILENAME_PREFIX, element_info->index);
//        break;
//    default:
//        return GATEWAY_ERROR;
//    }
//
//    if (!read_keystorage_file(folder, filename, out_data, buf_sz, out_sz)) {
//        return GATEWAY_ERROR;
//    }
//    return GATEWAY_OK;
//}

/******************************************************************************/
// static int
// vs_secbox_gateway_del(vs_secbox_element_info_t* element_info)
//{
//    assert(element_info);
//
//    return -1;
//}

/******************************************************************************/
// static int
// vs_secbox_gateway_sign_data(vs_secbox_sign_info_t* sign_info,
//    const uint8_t* data,
//    size_t data_sz,
//    uint8_t* signature,
//    size_t buf_sz,
//    size_t* signature_sz)
//{
//    // prepare folder
//    char folder[FILENAME_MAX];
//    uint8_t buf[2048];
//    prepare_keystorage_folder(folder);
//    size_t priv_key_sz;
//
//    if (!sign_info || !data || !signature || !signature_sz) {
//        return GATEWAY_ERROR;
//    }
//
//    if (!read_keystorage_file(folder, OWN_PRIVATE_KEY_FILENAME, buf, sizeof(buf), &priv_key_sz)) {
//        return GATEWAY_ERROR;
//    }
//
//    int res = 0;
//    vsc_data_t privkey_data = vsc_data(buf, priv_key_sz);
//    vscf_key_provider_t* key_provider = vscf_key_provider_new();
//    vscf_error_t error;
//    vscf_impl_t* privkey_ctx = NULL;
//    vsc_buffer_t* sign_buff = NULL;
//
//    error.status = vscf_key_provider_setup_defaults(key_provider);
//    if (vscf_status_SUCCESS != error.status) {
//        res = GATEWAY_ERROR;
//        goto cleanup;
//    }
//
//    privkey_ctx = vscf_key_provider_import_private_key(key_provider, privkey_data, &error);
//    if (vscf_status_SUCCESS != error.status) {
//        res = GATEWAY_ERROR;
//        goto cleanup;
//    }
//
//    if (sign_info->data_is_hash) {
//        sign_buff = vsc_buffer_new_with_capacity(vscf_sign_hash_signature_len(privkey_ctx));
//
//        error.status = vscf_sign_hash(privkey_ctx, vsc_data(data, data_sz), sign_info->hash_type, sign_buff);
//
//        if (vscf_status_SUCCESS != error.status || !_mbedtls_sign_to_virgil(MBEDTLS_MD_SHA256,
//        vsc_buffer_begin(sign_buff), vsc_buffer_len(sign_buff), signature, buf_sz, signature_sz)) {
//            res = GATEWAY_ERROR;
//            goto cleanup;
//        }
//    }
//
// cleanup:
//    vscf_key_provider_delete(key_provider);
//    vscf_impl_delete(privkey_ctx);
//    vsc_buffer_delete(sign_buff);
//    return res;
//}

/******************************************************************************/
const vs_secbox_hal_impl_t *
vs_secbox_gateway() {
    return &_secbox_gateway;
}
