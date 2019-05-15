#include <string.h>
#include <stdbool.h>

#include "secbox_impl/secbox_files.h"
#include <virgil/iot/secbox/secbox.h>
#include "mailbox_keystorage.h"
#include "iotelic/keystorage_tl.h"
#include "iotelic/keystorage_private.h"
#include "converters_mbedtls.h"
#include <mbedtls/asn1.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/sha256.h>
#include "gateway_macro.h"
static tl_context_t _tl_static_ctx;

static tl_context_t _tl_dynamic_ctx;

static tl_context_t _tl_tmp_ctx;


// static bool
//_verify_tl_signature(const uint8_t *hash,
//                     size_t hash_sz,
//                     const KEYSTORAGE_SLOT slots[PROVISION_KEYS_QTY],
//                     crypto_signature_t *sign,
//                     mbedtls_ecp_group_id sign_type) {
//    crypto_signed_hl_public_key_t key;
//    size_t read_sz;
//
//    for (int i = 0; i < PROVISION_KEYS_QTY; ++i) {
//
//        if (GATEWAY_OK == keystorage_load(slots[i], (uint8_t *)&key, sizeof(crypto_signed_hl_public_key_t), &read_sz)
//        &&
//            key.public_key.id.key_id == sign->signer_id.key_id &&
//            keystorage_verify_hl_key_sign((uint8_t *)&key, sizeof(key))) {
//            if (_tiny_verify_hash(hash, hash_sz, sign->val, sign_type, key.public_key.val)) {
//                return true;
//            }
//        }
//    }
//
//    return false;
//}
//
///******************************************************************************/
// static bool
//_verify_tl_signatures(const uint8_t *hash,
//                      HASH_TYPE hash_type,
//                      crypto_signature_t signs[TL_SIGNATURES_QTY],
//                      mbedtls_ecp_group_id sign_type) {
//
//    int hash_sz = hash_size(hash_type);
//    if (hash_sz < 0 || !_verify_tl_signature(hash, (size_t)hash_sz, auth_key_slot, &signs[0], sign_type) ||
//        !_verify_tl_signature(hash, (size_t)hash_sz, tl_key_slot, &signs[1], sign_type)) {
//        LOG("TL verify failed");
//        return false;
//    }
//    return true;
//}

/******************************************************************************/
static bool
_verify_tl(tl_context_t *tl_ctx) {
    trust_list_header_t header;
    trust_list_pub_key_t key;
    trust_list_footer_t footer;
    uint16_t i;
    //    mbedtls_sha256_context ctx;
    //    int hash_sz = hash_size(HASH_SHA_256);
    //
    //    if (hash_sz < 0) {
    //
    //        return false;
    //    }
    //    uint8_t hash[hash_sz];

    tl_ctx->ready = true;
    if (GATEWAY_OK != keystorage_load_tl_header(tl_ctx->storage.storage_type, &header)) {
        tl_ctx->ready = false;
        return false;
    }

    uint32_t tl_size = header.pub_keys_count * sizeof(trust_list_pub_key_t) + sizeof(trust_list_header_t) +
                       sizeof(trust_list_footer_t);

    //    mbedtls_sha256_init(&ctx);
    //    mbedtls_sha256_starts(&ctx, false);
    //    mbedtls_sha256_update(&ctx, (uint8_t *)&header, sizeof(trust_list_header_t));


    if (header.tl_size > TL_STORAGE_SIZE || header.tl_size != tl_size) {
        tl_ctx->ready = false;
        return false;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {

        if (GATEWAY_OK != keystorage_load_tl_key(tl_ctx->storage.storage_type, i, &key)) {
            tl_ctx->ready = false;
            return false;
        }
        //        mbedtls_sha256_update(&ctx, (uint8_t *)&key, sizeof(trust_list_pub_key_t));
    }

    //    mbedtls_sha256_finish(&ctx, hash);
    //    mbedtls_sha256_free(&ctx);

    if (GATEWAY_OK != keystorage_load_tl_footer(tl_ctx->storage.storage_type, &footer)/* ||
        !_verify_tl_signatures(hash, HASH_SHA_256, &footer.auth_sign, MBEDTLS_ECP_DP_SECP256R1)*/) {
        tl_ctx->ready = false;
        return false;
    }

    return true;
}

/******************************************************************************/
static void
_init_tl_ctx(size_t storage_type, tl_context_t *ctx) {
    if (!ctx)
        return;

    memset(&ctx->keys_qty, 0, sizeof(tl_keys_qty_t));
    ctx->ready = false;
    ctx->storage.storage_type = storage_type;
}


/******************************************************************************/
static tl_context_t *
_get_tl_ctx(size_t storage_type) {
    switch (storage_type) {
    case TL_STORAGE_TYPE_STATIC:
        return &_tl_static_ctx;
    case TL_STORAGE_TYPE_DYNAMIC:
        return &_tl_dynamic_ctx;
    case TL_STORAGE_TYPE_TMP:
        return &_tl_tmp_ctx;
    default:
        break;
    }
    return NULL;
}

/******************************************************************************/
static int
_copy_tl_file(tl_context_t *dst, tl_context_t *src) {
    trust_list_header_t header;
    trust_list_pub_key_t key;
    trust_list_footer_t footer;
    uint16_t i;

    if (!src->ready) {
        return KEYSTORAGE_ERROR_GENERAL;
    }

    if (GATEWAY_OK != keystorage_load_tl_header(src->storage.storage_type, &header) ||
        GATEWAY_OK != keystorage_save_tl_header(dst->storage.storage_type, &header)) {
        dst->ready = false;
        return KEYSTORAGE_ERROR_FLASH_WRITE;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {
        if (GATEWAY_OK != keystorage_load_tl_key(src->storage.storage_type, i, &key) ||
            GATEWAY_OK != keystorage_save_tl_key(dst->storage.storage_type, &key)) {
            dst->ready = false;
            return KEYSTORAGE_ERROR_FLASH_WRITE;
        }
    }

    if (GATEWAY_OK != keystorage_load_tl_footer(src->storage.storage_type, &footer) ||
        GATEWAY_OK != keystorage_save_tl_footer(dst->storage.storage_type, &footer)) {
        dst->ready = false;
        return KEYSTORAGE_ERROR_FLASH_WRITE;
    }

    dst->ready = true;
    dst->keys_qty.keys_amount = src->keys_qty.keys_amount;
    dst->keys_qty.keys_count = src->keys_qty.keys_count;

    return GATEWAY_OK;
}

/******************************************************************************/
bool
keystorage_verify_hl_key_sign(const uint8_t *key_to_check, size_t key_size) {
    //    uint8_t hash[32];
    size_t temp;

    if (!key_to_check || sizeof(crypto_signed_hl_public_key_t) != key_size) {
        return false;
    }

    crypto_signed_hl_public_key_t *key = (crypto_signed_hl_public_key_t *)key_to_check;
    crypto_signed_hl_public_key_t rec_key;

    //    if (GATEWAY_OK != hash_create(HASH_SHA_256, key->public_key.val, PUBKEY_TINY_SZ, hash, sizeof(hash), &temp)) {
    //        return false;
    //    }

    for (size_t i = 0; i < PROVISION_KEYS_QTY; ++i) {
        vs_secbox_element_info_t el;
        el.id = VS_SECBOX_ELEMENT_PBR;
        el.index = i;
        if (GATEWAY_OK == vs_secbox_load(&el, (uint8_t *)&rec_key, sizeof(crypto_signed_hl_public_key_t), &temp) &&
            rec_key.public_key.id.key_id == key->sign.signer_id.key_id /*&&
            _tiny_verify_hash(hash, sizeof(hash), key->sign.val, MBEDTLS_ECP_DP_SECP256R1, rec_key.public_key.val)*/) {
            return true;
        }
    }
    return false;
}

/******************************************************************************/
void
init_keystorage_tl() {
    _init_tl_ctx(TL_STORAGE_TYPE_DYNAMIC, &_tl_dynamic_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_STATIC, &_tl_static_ctx);
    _init_tl_ctx(TL_STORAGE_TYPE_TMP, &_tl_tmp_ctx);

    if (!_verify_tl(&_tl_dynamic_ctx) && _verify_tl(&_tl_static_ctx)) {
        if (GATEWAY_OK == _copy_tl_file(&_tl_dynamic_ctx, &_tl_static_ctx)) {
            _verify_tl(&_tl_dynamic_ctx);
        }
    }
}
/******************************************************************************/
int
keystorage_save_tl_header(size_t storage_type, const trust_list_header_t *header) {

    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (!header || NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    uint32_t tl_size = header->pub_keys_count * sizeof(trust_list_pub_key_t) + sizeof(trust_list_header_t) +
                       sizeof(trust_list_footer_t);

    if (header->tl_size > TL_STORAGE_SIZE || header->tl_size != tl_size) {
        return KEYSTORAGE_ERROR_SMALL_BUFFER;
    }

    tl_ctx->ready = false;
    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = header->pub_keys_count;


    if (write_tl_header_file(tl_ctx, header)) {
        return GATEWAY_OK;
    }

    return KEYSTORAGE_ERROR_FLASH_WRITE;
}

/******************************************************************************/
int
keystorage_load_tl_header(size_t storage_type, trust_list_header_t *header) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    if (!tl_ctx->ready) {
        return KEYSTORAGE_ERROR_GENERAL;
    }

    if (read_tl_header_file(tl_ctx, header)) {
        return GATEWAY_OK;
    }

    return KEYSTORAGE_ERROR_FLASH_READ;
}

/******************************************************************************/
int
keystorage_save_tl_footer(size_t storage_type, const trust_list_footer_t *footer) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx || tl_ctx->keys_qty.keys_amount != tl_ctx->keys_qty.keys_count) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    if (write_tl_footer_file(tl_ctx, footer)) {
        return GATEWAY_OK;
    }

    return KEYSTORAGE_ERROR_FLASH_WRITE;
}

/******************************************************************************/
int
keystorage_load_tl_footer(size_t storage_type, trust_list_footer_t *footer) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    if (!tl_ctx->ready) {
        return KEYSTORAGE_ERROR_GENERAL;
    }

    if (read_tl_footer_file(tl_ctx, footer)) {
        return GATEWAY_OK;
    }
    return KEYSTORAGE_ERROR_FLASH_READ;
}

/******************************************************************************/
int
keystorage_save_tl_key(size_t storage_type, const trust_list_pub_key_t *key) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    if (tl_ctx->keys_qty.keys_count >= tl_ctx->keys_qty.keys_amount) {
        tl_ctx->keys_qty.keys_count = tl_ctx->keys_qty.keys_amount;
        return KEYSTORAGE_ERROR_FLASH_WRITE;
    }

    if (!write_tl_key_file(tl_ctx, tl_ctx->keys_qty.keys_count, key)) {
        return KEYSTORAGE_ERROR_FLASH_WRITE;
    }

    tl_ctx->keys_qty.keys_count++;
    return GATEWAY_OK;
}

/******************************************************************************/
int
keystorage_load_tl_key(size_t storage_type, tl_key_handle handle, trust_list_pub_key_t *key) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    if (!tl_ctx->ready) {
        return KEYSTORAGE_ERROR_GENERAL;
    }

    if (read_tl_key_file(tl_ctx, handle, key)) {
        return GATEWAY_OK;
    }

    return KEYSTORAGE_ERROR_FLASH_READ;
}

/******************************************************************************/
int
keystorage_invalidate_tl(size_t storage_type) {
    trust_list_header_t header;
    size_t i;

    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    tl_ctx->keys_qty.keys_count = 0;
    tl_ctx->keys_qty.keys_amount = 0;

    if (GATEWAY_OK != keystorage_load_tl_header(storage_type, &header) || !remove_keystorage_tl_header_file(tl_ctx)) {
        return GATEWAY_OK;
    }

    tl_ctx->ready = false;

    if (!remove_keystorage_tl_footer_file(tl_ctx)) {
        return GATEWAY_OK;
    }

    for (i = 0; i < header.pub_keys_count; ++i) {
        if (!remove_keystorage_tl_key_file(tl_ctx, i)) {
            return GATEWAY_OK;
        }
    }

    return GATEWAY_OK;
}

/******************************************************************************/
int
keystorage_apply_tmp_tl_to(size_t storage_type) {
    tl_context_t *tl_ctx = _get_tl_ctx(storage_type);

    if (NULL == tl_ctx) {
        return KEYSTORAGE_ERROR_PARAMS;
    }

    if (_verify_tl(&_tl_tmp_ctx)) {
        if (GATEWAY_OK != keystorage_invalidate_tl(storage_type)) {
            return KEYSTORAGE_ERROR_GENERAL;
        }

        return _copy_tl_file(tl_ctx, &_tl_tmp_ctx);
    }

    return KEYSTORAGE_ERROR_GENERAL;
}
