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

#include <virgil/iot/initializer/sdmp/prvs_implementation.h>
#include <virgil/iot/protocols/sdmp.h>

#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_impl.h>

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

#include <secbox.h>

#define VS_SECBOX_ELEMENT_PBR 0
#define VS_SECBOX_ELEMENT_PBA 1
#define VS_SECBOX_ELEMENT_PBT 2
#define VS_SECBOX_ELEMENT_PBF 3
#define VS_SECBOX_ELEMENT_SGN 4
#define VS_SECBOX_ELEMENT_TLH 6
#define VS_SECBOX_ELEMENT_TLC 7
#define VS_SECBOX_ELEMENT_TLF 8
#define VS_SECBOX_ELEMENT_GET_OWN_PUBKEY 5
#define SERIAL_SIZE 100

/******************************************************************************/
static int
vs_prvs_dnid(vs_sdmp_prvs_dnid_element_t *element) {
    // TODO: We need real types of devices
    element->device_type = 1;
    return 0;
}

/******************************************************************************/
static int
vs_prvs_save_data(vs_sdmp_prvs_element_t element_id, const uint8_t *data, uint16_t data_sz) {
    vs_secbox_element_info_t info;

    switch (element_id) {
    case VS_PRVS_PBR1:
        info.id = VS_SECBOX_ELEMENT_PBR;
        info.index = 0;
        break;
    case VS_PRVS_PBR2:
        info.id = VS_SECBOX_ELEMENT_PBR;
        info.index = 1;
        break;
    case VS_PRVS_PBA1:
        info.id = VS_SECBOX_ELEMENT_PBA;
        info.index = 0;
        break;
    case VS_PRVS_PBA2:
        info.id = VS_SECBOX_ELEMENT_PBA;
        info.index = 1;
        break;
    case VS_PRVS_PBT1:
        info.id = VS_SECBOX_ELEMENT_PBT;
        info.index = 0;
        break;
    case VS_PRVS_PBT2:
        info.id = VS_SECBOX_ELEMENT_PBT;
        info.index = 1;
        break;
    case VS_PRVS_PBF1:
        info.id = VS_SECBOX_ELEMENT_PBF;
        info.index = 0;
        break;
    case VS_PRVS_PBF2:
        info.id = VS_SECBOX_ELEMENT_PBF;
        info.index = 1;
        break;
    case VS_PRVS_SGNP:
        info.id = VS_SECBOX_ELEMENT_SGN;
        info.index = 1;
        break;
    default:
        return -1;
    }
    return vs_secbox_save(&info, data, data_sz);
}

/******************************************************************************/
static int
vs_prvs_load_data() {
    return -1;
}

/******************************************************************************/
static int
vs_prvs_device_info(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz) {
    int res = 0;
//    vs_secbox_element_info_t sign_secbox = {.id = VS_SECBOX_ELEMENT_SGN, .index = 0};
//    vs_secbox_element_info_t own_pubkey_secbox = {.id = VS_SECBOX_ELEMENT_GET_OWN_PUBKEY,
//                                                  .index = vscf_alg_id_SECP256R1};
//    uint16_t sign_sz = 0;
    uint16_t pubkey_sz = 0;

    vs_sdmp_mac_addr(0, &device_info->mac);
    device_info->manufacturer = 0xfedcba98;
    device_info->model = 0x87654321;
    memcpy(device_info->udid_of_device, device_info->mac.bytes, ETH_ADDR_LEN);
    memset(&device_info->udid_of_device[ETH_ADDR_LEN], 0x03, SERIAL_SIZE - ETH_ADDR_LEN);

    // Load signature and public key
//    if (0 != vs_secbox_load(&own_pubkey_secbox, device_info->own_key.pubkey, PUBKEY_MAX_SZ, &pubkey_sz) ||
//        0 != vs_secbox_load(&sign_secbox, (uint8_t *)&device_info->signature, buf_sz, &sign_sz)) {
//        res = -1;
//    }
    device_info->own_key.pubkey_sz = (uint8_t)pubkey_sz;

    return res;
}

/******************************************************************************/
static int
vs_prvs_finalize_storage(vs_sdmp_pubkey_t *asav_response) {
//    vs_secbox_element_info_t el = {.id = VS_SECBOX_ELEMENT_GET_OWN_PUBKEY, .index = vscf_alg_id_SECP256R1};
//    uint16_t pubkey_sz;

//    if (0 != vs_secbox_load(&el, asav_response->pubkey, PUBKEY_MAX_SZ, &pubkey_sz) || pubkey_sz > UINT8_MAX) {
//        return -1;
//    }

    return 0;
}

/******************************************************************************/
static int
vs_prvs_start_save_tl(const uint8_t *data, uint16_t data_sz) {
    vs_secbox_element_info_t info;

    info.id = VS_SECBOX_ELEMENT_TLH;
    info.index = 0;

    return vs_secbox_save(&info, data, data_sz);
}

/******************************************************************************/
static int
vs_prvs_save_tl_part(const uint8_t *data, uint16_t data_sz) {
    vs_secbox_element_info_t info;

    info.id = VS_SECBOX_ELEMENT_TLC;
    info.index = 0;

    return vs_secbox_save(&info, data, data_sz);
}

/******************************************************************************/
static int
vs_prvs_finalize_tl(const uint8_t *data, uint16_t data_sz) {
    vs_secbox_element_info_t info;

    info.id = VS_SECBOX_ELEMENT_TLF;
    info.index = 0;

    return vs_secbox_save(&info, data, data_sz);
}

/******************************************************************************/
static int
vs_prvs_sign_data(const uint8_t *data, uint16_t data_sz, uint8_t *signature, uint16_t buf_sz, uint16_t *signature_sz) {
//    vs_secbox_sign_info_t info = {.data_is_hash = true, .hash_type = vscf_alg_id_SHA256};
    return 0;
}

/******************************************************************************/
vs_sdmp_prvs_impl_t
vs_prvs_impl() {
    vs_sdmp_prvs_impl_t res;

    memset(&res, 0, sizeof(res));

    res.dnid_func = vs_prvs_dnid;
    res.save_data_func = vs_prvs_save_data;
    res.load_data_func = vs_prvs_load_data;
    res.device_info_func = vs_prvs_device_info;
    res.finalize_storage_func = vs_prvs_finalize_storage;
    res.start_save_tl_func = vs_prvs_start_save_tl;
    res.save_tl_part_func = vs_prvs_save_tl_part;
    res.finalize_tl_func = vs_prvs_finalize_tl;
    res.sign_data_func = vs_prvs_sign_data;

    return res;
}