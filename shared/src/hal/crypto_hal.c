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
#include <stdlib.h>
#include <stdint.h>

#include "private/helpers.h"

#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/converters/crypto_format_converters.h>

#include <virgil/crypto/foundation/vscf_secp256r1_private_key.h>
#include <virgil/crypto/foundation/vscf_secp256r1_public_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_private_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_public_key.h>
#include <virgil/crypto/foundation/vscf_ed25519_private_key.h>
#include <virgil/crypto/foundation/vscf_ed25519_public_key.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_rsa_private_key.h>
#include <virgil/crypto/foundation/vscf_rsa_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_sha384.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_sign_hash.h>
#include <virgil/crypto/foundation/vscf_verify_hash.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_compute_shared_key.h>
#include <virgil/crypto/foundation/vscf_aes256_gcm.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_data.h>
#include <virgil/crypto/foundation/vscf_kdf2.h>
#include <mbedtls/ctr_drbg.h>

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
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(data);
    NOT_ZERO(data_sz);
    NOT_ZERO(hash);
    NOT_ZERO(hash_buf_sz);
    NOT_ZERO(hash_sz);

    VS_LOG_DEBUG("Generate hash %s for data size %d", vs_hsm_hash_type_descr(hash_type), data_sz);

    in_data = vsc_data(data, data_sz);

    vsc_buffer_init(&out_data);
    vsc_buffer_use(&out_data, hash, hash_buf_sz);

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
        goto terminate;
    }

    *hash_sz = vsc_buffer_len(&out_data);

    VS_LOG_DEBUG("Hash size %d, type %s", *hash_sz, vs_hsm_hash_type_descr(hash_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Hash : ", hash, *hash_sz);

    res = VS_HSM_ERR_OK;

terminate:

    if (VS_HSM_ERR_OK != res) {
        vsc_buffer_cleanup(&out_data);
    }

    return res;
}

/********************************************************************************/
static int
_load_prvkey(vs_iot_hsm_slot_e key_slot, vscf_impl_t **prvkey, vs_hsm_keypair_type_e *keypair_type) {
    uint8_t prvkey_buf[MAX_KEY_SZ];
    uint16_t prvkey_buf_sz = sizeof(prvkey_buf);
    vsc_data_t prvkey_data;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(prvkey);
    NOT_ZERO(keypair_type);

    CHECK_HSM(vs_hsm_keypair_get_prvkey(key_slot, prvkey_buf, prvkey_buf_sz, &prvkey_buf_sz, keypair_type),
              "Unable to load private key data from slot %s",
              get_slot_name(key_slot));

    prvkey_data = vsc_data(prvkey_buf, prvkey_buf_sz);

    switch (*keypair_type) {
    case VS_KEYPAIR_EC_SECP256R1:
        *prvkey = vscf_secp256r1_private_key_impl(vscf_secp256r1_private_key_new());
        CHECK_VSCF(vscf_secp256r1_private_key_import_private_key((vscf_secp256r1_private_key_t *)*prvkey, prvkey_data),
                   "Unable to import private key");
        break;

    case VS_KEYPAIR_EC_CURVE25519:
        *prvkey = vscf_curve25519_private_key_impl(vscf_curve25519_private_key_new());
        CHECK_VSCF(
                vscf_curve25519_private_key_import_private_key((vscf_curve25519_private_key_t *)*prvkey, prvkey_data),
                "Unable to import private key");
        break;

    case VS_KEYPAIR_EC_ED25519:
        *prvkey = vscf_ed25519_private_key_impl(vscf_ed25519_private_key_new());
        CHECK_VSCF(vscf_ed25519_private_key_import_private_key((vscf_ed25519_private_key_t *)*prvkey, prvkey_data),
                   "Unable to import private key");
        break;

    case VS_KEYPAIR_RSA_2048:
        *prvkey = vscf_rsa_private_key_impl(vscf_rsa_private_key_new());
        CHECK_VSCF(vscf_rsa_private_key_import_private_key((vscf_rsa_private_key_t *)*prvkey, prvkey_data),
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
static int
_create_pubkey_ctx(vs_hsm_keypair_type_e keypair_type,
                   const uint8_t *public_key,
                   uint16_t public_key_sz,
                   vscf_impl_t **pubkey) {

    *pubkey = NULL;
    int res = VS_HSM_ERR_OK;

    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP256R1:
        *pubkey = vscf_secp256r1_public_key_impl(vscf_secp256r1_public_key_new());
        if (vscf_status_SUCCESS != vscf_secp256r1_public_key_import_public_key((vscf_secp256r1_public_key_t *)*pubkey,
                                                                               vsc_data(public_key, public_key_sz))) {
            res = VS_HSM_ERR_CRYPTO;
            VS_LOG_ERROR("Unable to import public key");
        }
        break;

    case VS_KEYPAIR_EC_CURVE25519:
        *pubkey = vscf_curve25519_public_key_impl(vscf_curve25519_public_key_new());
        if (vscf_status_SUCCESS != vscf_curve25519_public_key_import_public_key((vscf_curve25519_public_key_t *)*pubkey,
                                                                                vsc_data(public_key, public_key_sz))) {
            res = VS_HSM_ERR_CRYPTO;
            VS_LOG_ERROR("Unable to import public key");
        }
        break;

    case VS_KEYPAIR_EC_ED25519:
        *pubkey = vscf_ed25519_public_key_impl(vscf_ed25519_public_key_new());
        if (vscf_status_SUCCESS != vscf_ed25519_public_key_import_public_key((vscf_ed25519_public_key_t *)*pubkey,
                                                                             vsc_data(public_key, public_key_sz))) {
            res = VS_HSM_ERR_CRYPTO;
            VS_LOG_ERROR("Unable to import public key");
        }
        break;

    case VS_KEYPAIR_RSA_2048:
        *pubkey = vscf_rsa_public_key_impl(vscf_rsa_public_key_new());
        if (vscf_status_SUCCESS != vscf_rsa_public_key_import_public_key((vscf_rsa_public_key_t *)*pubkey,
                                                                         vsc_data(public_key, public_key_sz))) {
            res = VS_HSM_ERR_CRYPTO;
            VS_LOG_ERROR("Unable to import public key");
        }
        break;

    default:
        VS_LOG_ERROR("Unsupported keypair type %d (%s)", keypair_type, vs_hsm_keypair_type_descr(keypair_type));
        res = VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    return res;
}

/********************************************************************************/
static bool
_set_hash_info(vs_hsm_hash_type_e hash_type, vscf_alg_id_t *hash_id, uint16_t *hash_sz) {

    *hash_sz = (uint16_t)vs_hsm_get_hash_len(hash_type);

    switch (hash_type) {
    case VS_HASH_SHA_256:
        *hash_id = vscf_alg_id_SHA256;
        return true;

    case VS_HASH_SHA_384:
        *hash_id = vscf_alg_id_SHA384;
        return true;

    case VS_HASH_SHA_512:
        *hash_id = vscf_alg_id_SHA512;
        return true;

    default:
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
    vscf_alg_id_t hash_id = vscf_alg_id_NONE;
    uint16_t hash_sz = 0;
    vsc_buffer_t sign_data;
    vs_hsm_keypair_type_e keypair_type = VS_KEYPAIR_INVALID;
    uint16_t required_sign_sz = 0;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(hash);
    NOT_ZERO(signature);
    NOT_ZERO(signature_buf_sz);
    NOT_ZERO(signature_sz);

    vsc_buffer_init(&sign_data);

    CHECK_BOOL(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    CHECK_HSM(_load_prvkey(key_slot, &prvkey, &keypair_type),
              "Unable to load private key from slot %d (%s)",
              key_slot,
              get_slot_name((key_slot)));

    required_sign_sz = vscf_sign_hash_signature_len(prvkey);

    CHECK_BOOL(signature_buf_sz >= required_sign_sz,
               "Signature buffer size %d is less that required size %d",
               signature_buf_sz,
               required_sign_sz);

    vsc_buffer_use(&sign_data, signature, required_sign_sz);

    CHECK_VSCF(vscf_sign_hash(prvkey, vsc_data(hash, hash_sz), hash_id, &sign_data), "Unable to sign data");

    if (vsc_buffer_len(&sign_data) > signature_buf_sz) {
        VS_LOG_ERROR("Generated signature's size %d is bigger that buffer size %d",
                     (int)vsc_buffer_len(&sign_data),
                     signature_buf_sz);
        res = VS_HSM_ERR_NOMEM;
        goto terminate;
    }

    *signature_sz = vsc_buffer_len(&sign_data);

    VS_LOG_DEBUG("Internal signature size : %d bytes", *signature_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Internal signature : ", vsc_buffer_begin(&sign_data), *signature_sz);

    CHECK_BOOL(vs_converters_mbedtls_sign_to_raw(keypair_type,
                                                 vsc_buffer_begin(&sign_data),
                                                 *signature_sz,
                                                 signature,
                                                 signature_buf_sz,
                                                 signature_sz),
               "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Output signature size : %d bytes", *signature_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Output signature : ", signature, *signature_sz);

    res = VS_HSM_ERR_OK;

terminate:

    if (VS_HSM_ERR_OK != res) {
        vsc_buffer_cleanup(&sign_data);
    }

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
#define MAX_INT_SIGN_SIZE 256
    uint8_t int_sign[MAX_INT_SIGN_SIZE];
    uint16_t int_sign_sz = sizeof(int_sign);
    vscf_impl_t *pubkey = NULL;
    vscf_alg_id_t hash_id = vscf_alg_id_NONE;
    uint16_t hash_sz = 0;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(public_key);
    NOT_ZERO(public_key_sz);
    NOT_ZERO(hash);
    NOT_ZERO(signature);
    NOT_ZERO(signature_sz);

    CHECK_BOOL(vs_converters_raw_sign_to_mbedtls(
                       keypair_type, signature, signature_sz, int_sign, int_sign_sz, &int_sign_sz),
               "Unable to convert Virgil signature format to the raw one");

    VS_LOG_DEBUG("Internal signature size : %d bytes", int_sign_sz);
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Internal signature : ", int_sign, int_sign_sz);

    res = _create_pubkey_ctx(keypair_type, public_key, public_key_sz, &pubkey);
    if (VS_HSM_ERR_OK != res) {
        goto terminate;
    }

    res = VS_HSM_ERR_CRYPTO;

    CHECK_BOOL(_set_hash_info(hash_type, &hash_id, &hash_sz), "Unable to set hash info");

    CHECK_BOOL(vscf_verify_hash(pubkey, vsc_data(hash, hash_sz), hash_id, vsc_data(int_sign, int_sign_sz)),
               "Unable to verify signature");

    res = VS_HSM_ERR_OK;

terminate:

    vscf_impl_delete(pubkey);

    return res;

#undef MAX_INT_SIGN_SIZE
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

    vscf_kdf2_t *kdf2;
    vscf_impl_t *hash_impl;
    vsc_buffer_t out_buf;

    NOT_ZERO(input);
    NOT_ZERO(output);
    if (kdf_type != VS_KDF_2) {
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    kdf2 = vscf_kdf2_new();

    switch (hash_type) {
    case VS_HASH_SHA_256:
        hash_impl = vscf_sha256_impl(vscf_sha256_new());
        break;

    case VS_HASH_SHA_384:
        hash_impl = vscf_sha384_impl(vscf_sha384_new());
        break;

    case VS_HASH_SHA_512:
        hash_impl = vscf_sha512_impl(vscf_sha512_new());
        break;
    default:
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, output, output_sz);
    vscf_kdf2_take_hash(kdf2, hash_impl);
    vscf_kdf2_derive(kdf2, vsc_data(input, input_sz), output_sz, &out_buf);

    vscf_kdf2_delete(kdf2);
    return VS_HSM_ERR_OK;
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
static vscf_impl_t *random_impl = NULL;

static void
destroy_random_impl() {
    vscf_ctr_drbg_delete((vscf_ctr_drbg_t *)random_impl);
}

/********************************************************************************/
int
vs_hsm_random(uint8_t *output, uint16_t output_sz) {
    int res = VS_HSM_ERR_CRYPTO;
    vsc_buffer_t out_buf;
    uint16_t cur_off = 0;
    uint16_t cur_size = 0;

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, output, output_sz);

    if (!random_impl) {
        CHECK_MEM_ALLOC(random_impl = (vscf_impl_t *)vscf_ctr_drbg_new(),
                        "Unable to allocate random implementation context");

        atexit(destroy_random_impl);

        CHECK_VSCF(vscf_ctr_drbg_setup_defaults((vscf_ctr_drbg_t *)random_impl),
                   "Unable to initialize random number generator");
    }

    for (cur_off = 0; cur_off < output_sz; cur_off += MBEDTLS_CTR_DRBG_MAX_REQUEST) {
        cur_size = output_sz - cur_off;

        if (cur_size > MBEDTLS_CTR_DRBG_MAX_REQUEST) {
            cur_size = MBEDTLS_CTR_DRBG_MAX_REQUEST;
        }

        CHECK_VSCF(vscf_random(random_impl, cur_size, &out_buf), "Unable to generate random sequence");
    }

    res = VS_HSM_ERR_OK;

terminate:

    if (VS_HSM_ERR_OK != res) {
        vsc_buffer_cleanup(&out_buf);
    }

    return res;
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

    uint16_t key_len;
    vsc_buffer_t *out_buf = NULL;
    vsc_buffer_t tag_buf;
    vscf_aes256_gcm_t *aes256_gcm = NULL;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(key);
    NOT_ZERO(iv);
    NOT_ZERO(input);
    NOT_ZERO(output);
    NOT_ZERO(tag);

    key_len = key_bitlen / 8;

    if (VS_AES_GCM != aes_type || key_len != vscf_aes256_gcm_KEY_LEN) {
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    aes256_gcm = vscf_aes256_gcm_new();

    out_buf = vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len(aes256_gcm, buf_len));
    vsc_buffer_init(&tag_buf);
    vsc_buffer_use(&tag_buf, tag, tag_len);


    vscf_aes256_gcm_set_key(aes256_gcm, vsc_data(key, key_len));
    vscf_aes256_gcm_set_nonce(aes256_gcm, vsc_data(iv, iv_len));

    if (vscf_status_SUCCESS ==
        vscf_aes256_gcm_auth_encrypt(aes256_gcm, vsc_data(input, buf_len), vsc_data(add, add_len), out_buf, &tag_buf)) {
        res = VS_HSM_ERR_OK;
        memcpy(output, vsc_buffer_bytes(out_buf), buf_len);
    }

    vscf_aes256_gcm_delete(aes256_gcm);
    vsc_buffer_delete(out_buf);

    return res;
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

    uint16_t key_len;
    vsc_buffer_t *out_buf = NULL;
    vscf_aes256_gcm_t *aes256_gcm = NULL;
    int res = VS_HSM_ERR_CRYPTO;

    NOT_ZERO(key);
    NOT_ZERO(iv);
    NOT_ZERO(input);
    NOT_ZERO(output);
    NOT_ZERO(tag);

    key_len = key_bitlen / 8;

    if (VS_AES_GCM != aes_type || key_len != vscf_aes256_gcm_KEY_LEN) {
        return VS_HSM_ERR_NOT_IMPLEMENTED;
    }

    aes256_gcm = vscf_aes256_gcm_new();

    out_buf = vsc_buffer_new_with_capacity(vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, buf_len));

    vscf_aes256_gcm_set_key(aes256_gcm, vsc_data(key, key_len));
    vscf_aes256_gcm_set_nonce(aes256_gcm, vsc_data(iv, iv_len));

    if (vscf_status_SUCCESS ==
        vscf_aes256_gcm_auth_decrypt(
                aes256_gcm, vsc_data(input, buf_len), vsc_data(add, add_len), vsc_data(tag, tag_len), out_buf)) {
        res = VS_HSM_ERR_OK;
        memcpy(output, vsc_buffer_bytes(out_buf), buf_len);
    }

    vscf_aes256_gcm_delete(aes256_gcm);
    vsc_buffer_delete(out_buf);

    return res;
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
    vscf_impl_t *prvkey = NULL;
    vscf_impl_t *pubkey = NULL;
    vsc_buffer_t out_buf;
    size_t required_sz;

    int res;

    NOT_ZERO(public_key);
    NOT_ZERO(shared_secret);
    NOT_ZERO(shared_secret_sz);

    CHECK_HSM(_load_prvkey(slot, &prvkey, &keypair_type),
              "Unable to load private key from slot %d (%s)",
              slot,
              get_slot_name((slot)));

    if ((required_sz = vscf_compute_shared_key_shared_key_len(prvkey)) > buf_sz) {
        VS_LOG_ERROR("Output buffer too small");
        res = VS_HSM_ERR_INVAL;
        goto terminate;
    }
    *shared_secret_sz = (uint16_t)required_sz;

    vsc_buffer_init(&out_buf);
    vsc_buffer_use(&out_buf, shared_secret, buf_sz);

    res = _create_pubkey_ctx(keypair_type, public_key, public_key_sz, &pubkey);

    if (VS_HSM_ERR_OK == res) {
        res = (vscf_status_SUCCESS == vscf_compute_shared_key(prvkey, pubkey, &out_buf)) ? VS_HSM_ERR_OK
                                                                                         : VS_HSM_ERR_CRYPTO;
    }

terminate:
    vscf_impl_delete(prvkey);
    vscf_impl_delete(pubkey);
    return res;
}
