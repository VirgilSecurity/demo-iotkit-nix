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
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <stdlib-config.h>

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

/******************************************************************************/
static int
vs_prvs_dnid() {
    return 0;
}

/******************************************************************************/
static int
vs_prvs_device_info(vs_sdmp_prvs_devi_t *device_info, uint16_t buf_sz) {
    uint16_t key_sz = 0;
    vs_hsm_keypair_type_e ec_type;
    vs_pubkey_t *own_pubkey;
    uint16_t sign_sz = 0;
    vs_sign_t *sign;

    VS_IOT_ASSERT(device_info);

    own_pubkey = (vs_pubkey_t *)device_info->data;
    vs_sdmp_mac_addr(0, &device_info->mac);
    device_info->manufacturer = 0x89abcdef;
    device_info->model = 0x12345678;
    VS_IOT_MEMCPY(device_info->udid_of_device, device_info->mac.bytes, ETH_ADDR_LEN);
    VS_IOT_MEMSET(&device_info->udid_of_device[ETH_ADDR_LEN], 0x03, 32 - ETH_ADDR_LEN);

    // Fill own public key
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
    if (0 != vs_hsm_slot_load(SIGNATURE_SLOT, (uint8_t *)sign, buf_sz, &sign_sz)) {
        return -1;
    }

    device_info->data_sz += sign_sz;

    return 0;
}

/******************************************************************************/
vs_sdmp_prvs_impl_t
vs_prvs_impl() {
    vs_sdmp_prvs_impl_t res;

    memset(&res, 0, sizeof(res));

    res.dnid_func = vs_prvs_dnid;
    res.device_info_func = vs_prvs_device_info;
    res.wait_func = NULL;
    res.stop_wait_func = NULL;

    return res;
}