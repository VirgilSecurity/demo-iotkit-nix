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
#include <stdarg.h>
#include <stdint.h>

#include <hal_helpers.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/logger/logger.h>

#include <virgil/crypto/foundation/vscf_secp256r1_private_key.h>
#include <virgil/crypto/foundation/vscf_secp256r1_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_sha384.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_signer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_data.h>

// memory layout for keypair save/load buffer:
// . vs_hsm_keypair_type_e key_type
// . uint8_t prvkey_sz
// . uint8_t prvkey[]
// . uint8_t pubkey_sz
// . uint8_t pubkey[]

#define KEYPAIR_BUF_SZ (sizeof(vs_hsm_keypair_type_e) + (MAX_KEY_SZ + sizeof(MAX_KEY_SZ)) * 2)

#define KEYPAIR_BUF_KEYTYPE_OFF 0
#define KEYPAIR_BUF_KEYTYPE_SIZEOF 1

#define KEYPAIR_BUF_PRVKEYSZ_OFF (KEYPAIR_BUF_KEYTYPE_OFF + KEYPAIR_BUF_KEYTYPE_SIZEOF)
#define KEYPAIR_BUF_PRVKEYSZ_SIZEOF 1

#define KEYPAIR_BUF_PRVKEY_OFF (KEYPAIR_BUF_PRVKEYSZ_OFF + KEYPAIR_BUF_PRVKEYSZ_SIZEOF)
#define KEYPAIR_BUF_PRVKEY_SIZEOF(BUF) ((BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF])

#define KEYPAIR_BUF_PUBKEYSZ_OFF(BUF) (KEYPAIR_BUF_PRVKEY_OFF + KEYPAIR_BUF_PRVKEY_SIZEOF(BUF))
#define KEYPAIR_BUF_PUBKEYSZ_SIZEOF 1

#define KEYPAIR_BUF_PUBKEY_OFF(BUF) (KEYPAIR_BUF_PUBKEYSZ_OFF(BUF) + KEYPAIR_BUF_PUBKEYSZ_SIZEOF)
#define KEYPAIR_BUF_PUBKEY_SIZEOF(BUF) ((BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)])

/********************************************************************************/
static int
vs_hsm_secp256r1_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_secp256r1_private_key_t *prvkey_ctx = NULL;
    vscf_secp256r1_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    int res = VS_HSM_ERR_CRYPTO;

    VS_LOG_DEBUG(
            "Keypair %s generate and save to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(prvkey_ctx = vscf_secp256r1_private_key_new(),
                    "Unable to allocate memory for slot %s",
                    get_slot_name(slot));

    CHECK_VSCF(vscf_secp256r1_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_secp256r1_private_key_generate_key(prvkey_ctx),
               "Unable to generate private key memory for slot %s",
               get_slot_name(slot));

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    buf[KEYPAIR_BUF_KEYTYPE_OFF] = keypair_type;
    vsc_buffer_inc_used(&keypair_buf, KEYPAIR_BUF_KEYTYPE_SIZEOF);

    key_sz = vscf_secp256r1_private_key_exported_private_key_len(prvkey_ctx);
    if (key_sz > MAX_KEY_SZ) {
        VS_LOG_ERROR("Too big private key : %d bytes. Maximum allowed size : %d", key_sz, MAX_KEY_SZ);
        goto terminate;
    }
    buf[KEYPAIR_BUF_PRVKEYSZ_OFF] = key_sz;
    vsc_buffer_inc_used(&keypair_buf, KEYPAIR_BUF_PRVKEYSZ_SIZEOF);

    CHECK_VSCF(vscf_secp256r1_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to save private key");

    VS_LOG_DEBUG("Private key size : %d", key_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Private key : ", buf + KEYPAIR_BUF_PRVKEY_OFF, key_sz);


    CHECK_MEM_ALLOC(pubkey_ctx =
                            (vscf_secp256r1_public_key_t *)vscf_secp256r1_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory for slot %s",
                    get_slot_name(slot));

    key_sz = vscf_secp256r1_public_key_exported_public_key_len(pubkey_ctx);
    if (key_sz > MAX_KEY_SZ) {
        VS_LOG_ERROR("Too big public key : %d bytes. Maximum allowed size : %d", key_sz, MAX_KEY_SZ);
        goto terminate;
    }
    buf[KEYPAIR_BUF_PUBKEYSZ_OFF(buf)] = key_sz;
    vsc_buffer_inc_used(&keypair_buf, KEYPAIR_BUF_PUBKEYSZ_SIZEOF);

    CHECK_VSCF(vscf_secp256r1_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    VS_LOG_DEBUG("Public key size : %d", key_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Public key : ", buf + KEYPAIR_BUF_PUBKEY_OFF(buf), key_sz);

    CHECK_HSM(vs_hsm_slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
              "Unable to save keypair buffer to the slot %s",
              get_slot_name(slot));

    res = VS_HSM_ERR_OK;

terminate:

    if (prvkey_ctx) {
        vscf_secp256r1_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_secp256r1_public_key_delete(pubkey_ctx);
    }

    return res;
}

/********************************************************************************/
int
vs_hsm_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP256R1:
        return vs_hsm_secp256r1_keypair_create(slot, keypair_type);

    default:
        VS_LOG_ERROR("Unsupported keypair type %s for slot %s",
                     vs_hsm_keypair_type_descr(keypair_type),
                     get_slot_name(slot));
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }
}

/********************************************************************************/
int
vs_hsm_keypair_get_pubkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type) {
    uint8_t keypair_buf[KEYPAIR_BUF_SZ];
    uint16_t keypair_buf_sz = sizeof(keypair_buf);
    uint8_t pubkey_sz;
    int res = VS_HSM_ERR_CRYPTO;

    CHECK_HSM(vs_hsm_slot_load(slot, keypair_buf, keypair_buf_sz, &keypair_buf_sz),
              "Unable to load data from slot %d (%s)",
              slot,
              get_slot_name(slot));

    pubkey_sz = keypair_buf[KEYPAIR_BUF_PUBKEYSZ_OFF(keypair_buf)];
    if (pubkey_sz == 0) {
        VS_LOG_ERROR("Zero size public key");
        goto terminate;
    }
    if (pubkey_sz > buf_sz) {
        VS_LOG_ERROR("Too big public key size %d while buffer has %d bytes", pubkey_sz, buf_sz);
        goto terminate;
    }

    memcpy(buf, keypair_buf + KEYPAIR_BUF_PUBKEY_OFF(keypair_buf), pubkey_sz);
    *key_sz = pubkey_sz;

    *keypair_type = keypair_buf[KEYPAIR_BUF_KEYTYPE_OFF];

    VS_LOG_DEBUG("Public key %d bytes from slot %s with keypair type %s has been loaded",
                 pubkey_sz,
                 get_slot_name(slot),
                 vs_hsm_keypair_type_descr(*keypair_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Public key : ", buf, *key_sz);

    res = VS_HSM_ERR_OK;

terminate:

    return res;
}

/********************************************************************************/
int
vs_hsm_keypair_get_prvkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type) {
    uint8_t keypair_buf[KEYPAIR_BUF_SZ];
    uint16_t keypair_buf_sz = sizeof(keypair_buf);
    uint8_t prvkey_sz;
    int res = VS_HSM_ERR_CRYPTO;

    CHECK_HSM(vs_hsm_slot_load(slot, keypair_buf, keypair_buf_sz, &keypair_buf_sz),
              "Unable to load data from slot %d (%s)",
              slot,
              get_slot_name(slot));

    prvkey_sz = keypair_buf[KEYPAIR_BUF_PRVKEYSZ_OFF];
    if (prvkey_sz == 0) {
        VS_LOG_ERROR("Zero size private key");
        goto terminate;
    }
    if (prvkey_sz > buf_sz) {
        VS_LOG_ERROR("Too big private key size %d while buffer has %d bytes", prvkey_sz, buf_sz);
        goto terminate;
    }

    memcpy(buf, keypair_buf + KEYPAIR_BUF_PRVKEY_OFF, prvkey_sz);
    *key_sz = prvkey_sz;

    *keypair_type = keypair_buf[KEYPAIR_BUF_KEYTYPE_OFF];

    VS_LOG_DEBUG("Private key %d bytes from slot %s with keypair type %s has been loaded",
                 prvkey_sz,
                 get_slot_name(slot),
                 vs_hsm_keypair_type_descr(*keypair_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Private key : ", buf, *key_sz);

    res = VS_HSM_ERR_OK;

terminate:

    return res;
}