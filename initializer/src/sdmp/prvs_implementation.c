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

#include "prvs_implementation.h"
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/status_code/status_code.h>
#include <stdlib-config.h>


#include <virgil/iot/secbox/secbox.h>

#include <hal/rpi-global-hal.h>

/******************************************************************************/
static vs_status_e
vs_prvs_dnid() {
    return VS_CODE_OK;
}

/******************************************************************************/
static void
_create_field(uint8_t *dst, const char *src, size_t elem_buf_size) {
    size_t pos;
    size_t len;

    assert(src && *src);
    assert(elem_buf_size);
    memset(dst, 0, elem_buf_size);

    len = strlen(src);
    for (pos = 0; pos < len && pos < elem_buf_size; ++pos, ++src, ++dst) {
        *dst = *src;
    }
}

/******************************************************************************/
static vs_status_e
vs_prvs_device_info(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz) {
    uint16_t key_sz = 0;
    vs_hsm_keypair_type_e ec_type;
    vs_pubkey_t *own_pubkey;
    uint16_t sign_sz = 0;
    vs_sign_t *sign;
    uint8_t *ptr;
    vs_status_e ret_code;

    VS_IOT_ASSERT(device_info);

    own_pubkey = (vs_pubkey_t *)device_info->data;
    vs_sdmp_mac_addr(0, &device_info->mac);
    // TODO: Need to move to 16 bytes MANUFACTURE_ID
    ptr = (uint8_t *)(&device_info->manufacturer);
    _create_field(ptr, MANUFACTURE_ID, sizeof(device_info->manufacturer));

    ptr = (uint8_t *)(&device_info->model);
    _create_field(ptr, DEVICE_MODEL, sizeof(device_info->model));

    vs_rpi_hal_get_udid(device_info->udid_of_device);

    // Fill own public key
    STATUS_CHECK_RET(vs_hsm_keypair_get_pubkey(PRIVATE_KEY_SLOT, own_pubkey->pubkey, PUBKEY_MAX_SZ, &key_sz, &ec_type), "Unable to get public key");

    own_pubkey->key_type = VS_KEY_IOT_DEVICE;
    own_pubkey->ec_type = ec_type;
    device_info->data_sz = key_sz + sizeof(vs_pubkey_t);
    sign = (vs_sign_t *)((uint8_t *)own_pubkey + key_sz + sizeof(vs_pubkey_t));

    buf_sz -= device_info->data_sz;

    // Load signature
    STATUS_CHECK_RET(vs_hsm_slot_load(SIGNATURE_SLOT, (uint8_t *)sign, buf_sz, &sign_sz), "Unable to load slot");

    device_info->data_sz += sign_sz;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_sdmp_prvs_impl_t
vs_prvs_impl() {
    vs_sdmp_prvs_impl_t res;

    memset(&res, 0, sizeof(res));

    res.dnid_func = vs_prvs_dnid;
    res.device_info_func = vs_prvs_device_info;

    return res;
}