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
#include <virgil/iot/converters/crypto_format_converters.h>

#include <virgil/crypto/foundation/vscf_secp256r1_private_key.h>
#include <virgil/crypto/foundation/vscf_secp256r1_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_sha384.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_sign_hash.h>
#include <virgil/crypto/foundation/vscf_verify_hash.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_data.h>

/********************************************************************************/
int
vs_hsm_hash_create(vs_hsm_hash_type_e hash_type,
                   const uint8_t *data,
                   uint16_t data_sz,
                   uint8_t *hash,
                   uint16_t hash_buf_sz,
                   uint16_t *hash_sz) {
    vsc_data_t in_data;
    vsc_buffer_t out_data;

    in_data = vsc_data(data, data_sz);
    vsc_buffer_init(&out_data);
    vsc_buffer_use(&out_data, hash, hash_buf_sz);

    NOT_ZERO(data);
    NOT_ZERO(data_sz);
    NOT_ZERO(hash);
    NOT_ZERO(hash_buf_sz);
    NOT_ZERO(hash_sz);

    VS_LOG_DEBUG("Generate hash %s for data size %d", vs_hsm_hash_type_descr(hash_type), data_sz);

    switch (hash_type) {
    case VS_HASH_SHA_256:
        vscf_sha256_hash(in_data, &out_data);
        break;

    case VS_HASH_SHA_384:
        vscf_sha384_hash(in_data, &out_data);
        break;

    case VS_HASH_SHA_512:
        vscf_sha512_hash(in_data, &out_data);
        break;

    default:
        assert(false && "Unsupported hash type");
        VS_LOG_ERROR("Unsupported hash type");
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    return VS_HSM_ERR_OK;
}

/********************************************************************************
static int
_init_hash_for_ecdsa_sign(vscf_signer_t *signer, vs_hsm_hash_type_e hash_type, const uint8_t *hash) {
    size_t hash_sz;

    switch (hash_type) {
    case VS_HASH_SHA_256:
        vscf_signer_take_hash(signer, vscf_sha256_impl(vscf_sha256_new()));
        hash_sz = 256 / 8;
        break;
    case VS_HASH_SHA_384:
        vscf_signer_take_hash(signer, vscf_sha384_impl(vscf_sha384_new()));
        hash_sz = 384 / 8;
        break;
    case VS_HASH_SHA_512:
        vscf_signer_take_hash(signer, vscf_sha512_impl(vscf_sha512_new()));
        hash_sz = 512 / 8;
        break;
    default:
        assert(false && "Unsupported hash type");
        VS_LOG_ERROR("Unsupported hash type %d", hash_type);
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    vscf_signer_update(signer, vsc_data(hash, hash_sz));

    return VS_HSM_ERR_OK;
}
*/

/********************************************************************************/
static int
_load_prvkey(vs_iot_hsm_slot_e key_slot, vscf_impl_t **prvkey, vs_hsm_keypair_type_e *keypair_type) {
    uint8_t prvkey_buf[MAX_KEY_SZ] = {0};
    uint16_t prvkey_buf_sz = sizeof(prvkey_buf);
    vsc_data_t prvkey_data;
    int res = VS_HSM_ERR_CRYPTO;

    CHECK_HSM(vs_hsm_keypair_get_prvkey(key_slot, prvkey_buf, prvkey_buf_sz, &prvkey_buf_sz, keypair_type),
              "Unable to load private key data from slot %s",
              get_slot_name(key_slot));

    prvkey_data = vsc_data(prvkey_buf, prvkey_buf_sz);

    switch (*keypair_type) {
    case VS_KEYPAIR_EC_SECP256R1:
        *prvkey = (vscf_impl_t *)vscf_secp256r1_private_key_new();
        CHECK_VSCF(vscf_secp256r1_private_key_import_private_key((vscf_secp256r1_private_key_t *)*prvkey, prvkey_data),
                   "Unable to import private key");
        break;

    default:
        assert(false && "Unsupported keypair type");
        VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_hsm_keypair_type_descr(*keypair_type));
        res = VS_HSM_ERR_NOT_IMPLEMENTED;
        goto terminate;
    }

    res = VS_HSM_ERR_OK;

terminate:

    return res;
}

/********************************************************************************/
static bool
_set_hsm_data(vs_hsm_hash_type_e hash_type, vscf_alg_id_t *hash_id, uint16_t *hash_sz) {
    switch (hash_type) {
    case VS_HASH_SHA_256:
        *hash_id = vscf_alg_id_SHA256;
        *hash_sz = 256 / 8;
        return true;

    case VS_HASH_SHA_384:
        *hash_id = vscf_alg_id_SHA384;
        *hash_sz = 384 / 8;
        return true;

    case VS_HASH_SHA_512:
        *hash_id = vscf_alg_id_SHA512;
        *hash_sz = 512 / 8;
        return true;

    default:
        assert(false && "Unsupported hash type");
        VS_LOG_ERROR("Unsupported hash type %d", hash_type);
        return false;
    }
}

/********************************************************************************/
int
vs_hsm_ecdsa_sign(vs_iot_hsm_slot_e key_slot,
                  vs_hsm_hash_type_e hash_type,
                  const uint8_t *hash,
                  uint8_t *signature,
                  uint16_t signature_buf_sz,
                  uint16_t *signature_sz) {
    vscf_impl_t *prvkey = NULL;
    vscf_alg_id_t hash_id;
    uint16_t hash_sz;
    vsc_buffer_t sign_data;
    vs_hsm_keypair_type_e keypair_type;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(hash);
    NOT_ZERO(signature);
    NOT_ZERO(signature_buf_sz);
    NOT_ZERO(signature_sz);

    vsc_buffer_init(&sign_data);
    vsc_buffer_use(&sign_data, signature, signature_buf_sz);

    CHECK_BOOL(_set_hsm_data(hash_type, &hash_id, &hash_sz), "Unable to set hash data");

    CHECK_HSM(_load_prvkey(key_slot, &prvkey, &keypair_type),
              "Unable to load private key from slot %s",
              get_slot_name((key_slot)));

    CHECK_VSCF(vscf_sign_hash(prvkey, vsc_data(hash, hash_sz), hash_id, &sign_data), "Unable to sign data");

    if (vsc_buffer_len(&sign_data) > signature_buf_sz) {
        VS_LOG_ERROR("Generated signature's size %d is bigger that buffer size %d",
                     (int)vsc_buffer_len(&sign_data),
                     signature_buf_sz);
        res = VS_HSM_ERR_NOMEM;
        goto terminate;
    }

    *signature_sz = vsc_buffer_len(&sign_data);

    CHECK_BOOL(vs_converters_mbedtls_sign_to_raw(keypair_type,
                                                 vsc_buffer_begin(&sign_data),
                                                 *signature_sz,
                                                 signature,
                                                 signature_buf_sz,
                                                 signature_sz),
               "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Signature size : %d bytes", *signature_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Signature : ", signature, *signature_sz);

    res = VS_HSM_ERR_OK;

terminate:

    if (prvkey) {
        vscf_impl_destroy(&prvkey);
    }

    return res;
}

/********************************************************************************/
int
vs_hsm_ecdsa_verify(vs_hsm_keypair_type_e keypair_type,
                    const uint8_t *public_key,
                    uint16_t public_key_sz,
                    vs_hsm_hash_type_e hash_type,
                    const uint8_t *hash,
                    const uint8_t *signature,
                    uint16_t signature_sz) {
    uint8_t int_sign[256];
    uint16_t int_sign_sz = sizeof(int_sign);
    vscf_impl_t *pubkey = NULL;
    vscf_alg_id_t hash_id;
    uint16_t hash_sz;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(public_key);
    NOT_ZERO(public_key_sz);
    NOT_ZERO(hash);
    NOT_ZERO(signature);
    NOT_ZERO(signature_sz);

    CHECK_BOOL(vs_converters_mbedtls_sign_to_virgil(
                       hash_type, signature, signature_sz, int_sign, int_sign_sz, &int_sign_sz),
               "Unable to convert Virgil signature format to the raw one");

    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP256R1:
        pubkey = (vscf_impl_t *)vscf_secp256r1_public_key_new();
        CHECK_VSCF(vscf_secp256r1_public_key_import_public_key((vscf_secp256r1_public_key_t *)pubkey,
                                                               vsc_data(public_key, public_key_sz)),
                   "Unable to import public key");
        break;

    default:
        assert(false && "Unsupported keypair type");
        VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_hsm_keypair_type_descr(keypair_type));
        res = VS_HSM_ERR_NOT_IMPLEMENTED;
        goto terminate;
    }

    CHECK_BOOL(_set_hsm_data(hash_type, &hash_id, &hash_sz), "Unable to set hash data");

    CHECK_VSCF(vscf_verify_hash(pubkey, vsc_data(hash, hash_sz), hash_id, vsc_data(int_sign, int_sign_sz)),
               "Unable to verify signature");

    res = VS_HSM_ERR_OK;

terminate:

    if (pubkey) {
        vscf_impl_destroy(&pubkey);
    }

    return res;
}

/********************************************************************************/
int
vs_hsm_hmac(vs_hsm_hash_type_e hash_type,
            const uint8_t *key,
            uint16_t key_sz,
            const uint8_t *input,
            uint16_t input_sz,
            uint8_t *output,
            uint16_t output_buf_sz,
            uint16_t *output_sz) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_kdf(vs_hsm_kdf_type_e kdf_type,
           vs_hsm_hash_type_e hash_type,
           const uint8_t *input,
           uint16_t input_sz,
           uint8_t *output,
           uint16_t output_sz) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_hkdf(vs_hsm_hash_type_e hash_type,
            const uint8_t *input,
            uint16_t input_sz,
            const uint8_t *salt,
            uint16_t salt_sz,
            const uint8_t *info,
            uint16_t info_sz,
            uint8_t *output,
            uint16_t output_sz) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_random(uint8_t *output, uint16_t output_sz) {
    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_aes_encrypt(vs_iot_aes_type_e aes_type,
                   const uint8_t *key,
                   uint16_t key_bitlen,
                   const uint8_t *iv,
                   uint16_t iv_len,
                   const uint8_t *add,
                   uint16_t add_len,
                   uint16_t buf_len,
                   const uint8_t *input,
                   uint8_t *output,
                   uint8_t *tag,
                   uint16_t tag_len) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_aes_decrypt(vs_iot_aes_type_e aes_type,
                   const uint8_t *key,
                   uint16_t key_bitlen,
                   const uint8_t *iv,
                   uint16_t iv_len,
                   const uint8_t *add,
                   uint16_t add_len,
                   uint16_t buf_len,
                   const uint8_t *input,
                   uint8_t *output,
                   uint8_t *tag,
                   uint16_t tag_len) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_aes_auth_decrypt(vs_iot_aes_type_e aes_type,
                        const uint8_t *key,
                        uint16_t key_bitlen,
                        const uint8_t *iv,
                        uint16_t iv_len,
                        const uint8_t *add,
                        uint16_t add_len,
                        uint16_t buf_len,
                        const uint8_t *input,
                        uint8_t *output,
                        const uint8_t *tag,
                        uint16_t tag_len) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}

/********************************************************************************/
int
vs_hsm_ecdh(vs_iot_hsm_slot_e slot,
            vs_hsm_keypair_type_e keypair_type,
            const uint8_t *public_key,
            uint16_t public_key_sz,
            uint8_t *shared_secret,
            uint16_t buf_sz,
            uint16_t *shared_secret_sz) {

    return VS_HSM_ERR_NOT_IMPLEMENTED;
}
