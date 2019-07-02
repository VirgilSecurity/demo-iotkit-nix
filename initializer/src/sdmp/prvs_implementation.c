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

#include <unistd.h>

#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/initializer/sdmp/prvs_implementation.h>
#include <virgil/iot/protocols/sdmp.h>

#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_impl.h>

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

#include <virgil/iot/secbox/secbox.h>

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
#define MAX_PUBKEY_SZ 100
#define MAX_SIGN_SZ 128
#define MANUFACTURER_ID  0x12A4B6D8
#define MODEL_ID 0x42486938

/******************************************************************************/
static int
vs_prvs_dnid() {
    return 0;
}

/******************************************************************************/
static int
vs_prvs_save_data(vs_sdmp_prvs_element_t element_id, const uint8_t *data, uint16_t data_sz) {
    vs_secbox_element_info_t info;

    // TODO : is it correct?
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
    uint16_t key_sz = 0;
    vs_hsm_keypair_type_e ec_type;
    vs_pubkey_t *own_pubkey;
    uint16_t sign_sz = 0;
    vs_sign_t *sign;

    assert(device_info);

    own_pubkey = (vs_pubkey_t *)device_info->data;
    vs_sdmp_mac_addr(0, &device_info->mac);
    // TODO : neet to check constants listed below
    device_info->manufacturer = MANUFACTURER_ID;
    device_info->model = MODEL_ID;
    memcpy(device_info->udid_of_device, device_info->mac.bytes, ETH_ADDR_LEN);
    memset(&device_info->udid_of_device[ETH_ADDR_LEN], 0x03, 32 - ETH_ADDR_LEN);

    // Fill own public key
    // TODO : is it necessary to save it?
    if (VS_HSM_ERR_OK !=
        vs_hsm_keypair_get_pubkey(PRIVATE_KEY_SLOT, own_pubkey->pubkey, PUBKEY_MAX_SZ, &key_sz, &ec_type)) {
        return -1;
    }

    own_pubkey->key_type = VS_KEY_IOT_DEVICE;
    own_pubkey->ec_type = ec_type;
    device_info->data_sz = key_sz + sizeof(vs_pubkey_t);
    sign = (vs_sign_t *)((uint8_t *)own_pubkey + key_sz + sizeof(vs_pubkey_t));

    buf_sz -= device_info->data_sz;

    // Load signature
    // TODO : has it been created before this call? Need to place check for this
    if (0 != vs_hsm_slot_load(SIGNATURE_SLOT, (uint8_t *)sign, buf_sz, &sign_sz)) {
        return -1;
    }

    device_info->data_sz += sign_sz;

    return 0;

}

/******************************************************************************/
static int
vs_prvs_finalize_storage(vs_pubkey_t *asav_response, uint16_t *resp_sz) {
    uint16_t key_sz = 0;
    vs_hsm_keypair_type_e ec_type;

    assert(asav_response);
    assert(resp_sz);

    if (VS_HSM_ERR_OK != vs_hsm_keypair_create(PRIVATE_KEY_SLOT, VS_KEYPAIR_EC_SECP256R1) ||
        VS_HSM_ERR_OK !=
        vs_hsm_keypair_get_pubkey(PRIVATE_KEY_SLOT, asav_response->pubkey, PUBKEY_MAX_SZ, &key_sz, &ec_type)) {
        return -1;
    }

    asav_response->key_type = VS_KEY_IOT_DEVICE;
    asav_response->ec_type = ec_type;
    *resp_sz = sizeof(vs_pubkey_t) + key_sz;

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
    uint16_t sign_sz;
    uint16_t pubkey_sz;

    assert(signature_sz);
    assert(data);
    assert(signature);

    vs_sdmp_prvs_sgnp_req_t *request = (vs_sdmp_prvs_sgnp_req_t *)data;
    vs_sign_t *response = (vs_sign_t *)signature;
    int hash_len = vs_hsm_get_hash_len(request->hash_type);
    vs_hsm_keypair_type_e keypair_type;

    if (hash_len <= 0 || buf_sz <= sizeof(vs_sign_t)) {
        return -1;
    }
    uint8_t hash[hash_len];
    buf_sz -= sizeof(vs_sign_t);

    if (VS_HSM_ERR_OK != vs_hsm_hash_create(request->hash_type,
                                            (uint8_t *)&request->data,
                                            data_sz - sizeof(vs_sdmp_prvs_sgnp_req_t),
                                            hash,
                                            hash_len,
                                            &sign_sz) ||
        VS_HSM_ERR_OK !=
        vs_hsm_ecdsa_sign(
                PRIVATE_KEY_SLOT, request->hash_type, hash, response->raw_sign_pubkey, buf_sz, &sign_sz)) {
        return -1;
    }

    buf_sz -= sign_sz;

    if (VS_HSM_ERR_OK !=
        vs_hsm_keypair_get_pubkey(
                PRIVATE_KEY_SLOT, response->raw_sign_pubkey + sign_sz, buf_sz, &pubkey_sz, &keypair_type)) {
        return -1;
    }

    response->signer_type = VS_KEY_IOT_DEVICE;
    response->hash_type = (uint8_t)request->hash_type;
    response->ec_type = (uint8_t)keypair_type;
    *signature_sz = sizeof(vs_sign_t) + sign_sz + pubkey_sz;

    return 0;
}

/******************************************************************************/
static int
vs_prvs_stop_wait(int *condition, int expect) {
    // TODO : not obvious what this function has to do
//    if (_event) {
//        os_set_event(_event);
//        return 0;
//   }
//   return -1;
    return 0;
}

/******************************************************************************/
static int
vs_prvs_wait(uint32_t wait_ms, int *condition, int idle) {
    // TODO : not obvious what this function has to do
    usleep(wait_ms * 1000);
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
    res.stop_wait_func = vs_prvs_stop_wait;
    res.wait_func = vs_prvs_wait;

    return res;
}