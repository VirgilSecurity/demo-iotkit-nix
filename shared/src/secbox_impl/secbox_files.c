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

#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include <stdbool.h>

#include "secbox_impl/secbox_files.h"
#include <virgil/iot/protocols/sdmp.h>
#include "communication/gateway_netif_plc.h"
#include "iotelic/keystorage_tl.h"
#include <sys/stat.h>

/******************************************************************************/
static bool
_file_is_exist(const char *folder, const char *file_name) {
    DIR *d;
    bool result = false;
    struct dirent *dir;

    d = opendir(folder);
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (0 == strcmp(dir->d_name, file_name)) {
                result = true;
                break;
            }
        }
        closedir(d);
    }
    return result;
}

/******************************************************************************/
static int
_mkdir_recursive(const char *dir) {
    char tmp[FILENAME_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO);
            *p = '/';
        }
    return mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO);
}

/******************************************************************************/
static bool
_write_file_data(const char *folder, const char *file_name, const uint8_t *data, size_t data_sz) {
    if (!folder || !file_name || !data)
        return false;

    DIR *d;
    d = opendir(folder);

    if (d) {
        closedir(d);
    } else {
        if (-1 == _mkdir_recursive(folder)) {
            return false;
        }
    }

    char file_path[FILENAME_MAX];
    snprintf(file_path, FILENAME_MAX, "%s/%s", folder, file_name);

    FILE *fp = fopen(file_path, "wb");
    bool result = false;

    if (fp) {
        if (fwrite((void *)data, data_sz, 1, fp)) {
            result = true;
        }
        fclose(fp);
    }

    return result;
}

/******************************************************************************/
bool
_read_file_data(const char *folder, const char *file_name, const uint8_t *data, size_t buf_sz, size_t *data_sz) {
    if (!folder || !file_name || !data)
        return false;

    bool result = false;

    char file_path[FILENAME_MAX];
    snprintf(file_path, FILENAME_MAX, "%s/%s", folder, file_name);

    FILE *fp = fopen(file_path, "rb");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long file_sz = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if (buf_sz >= file_sz && (1 == fread((void *)data, (size_t)file_sz, 1, fp))) {
            *data_sz = (size_t)file_sz;
            result = true;
        }

        fclose(fp);
    }
    return result;
}

/******************************************************************************/
static const char *
_storage_type_to_str(size_t storage_type) {
    switch (storage_type) {
    case TL_STORAGE_TYPE_STATIC:
        return "stat";
    case TL_STORAGE_TYPE_DYNAMIC:
        return "dyn";
    case TL_STORAGE_TYPE_TMP:
        return "tmp";
    default:
        break;
    }
    return "";
}

/******************************************************************************/
void
prepare_keystorage_folder(char folder[FILENAME_MAX]) {

    vs_mac_addr_t mac_addr;

    vs_hal_netif_plc()->mac_addr(&mac_addr);

    snprintf(folder,
             FILENAME_MAX,
             "%s/%x:%x:%x:%x:%x:%x",
             KEYSTORAGE_DIR,
             mac_addr.bytes[0],
             mac_addr.bytes[1],
             mac_addr.bytes[2],
             mac_addr.bytes[3],
             mac_addr.bytes[4],
             mac_addr.bytes[5]);
}

/******************************************************************************/
bool
write_keystorage_file(const char *folder, const char *file_name, const uint8_t *data, size_t data_sz) {
    return _write_file_data(folder, file_name, data, data_sz);
}

/******************************************************************************/
bool
read_keystorage_file(const char *folder, const char *file_name, uint8_t *out_data, size_t buf_sz, size_t *out_sz) {
    if (!folder || !file_name || !out_data)
        return false;

    bool result = false;
    *out_sz = 0;

    if (_file_is_exist(folder, file_name)) {
        if (_read_file_data(folder, file_name, (uint8_t *)out_data, buf_sz, out_sz)) {

            result = true;
        }
    }
    return result;
}

/******************************************************************************/
bool
write_tl_header_file(tl_context_t *ctx, const trust_list_header_t *tl_header) {
    char folder[FILENAME_MAX];
    char filename[FILENAME_MAX];

    if (!tl_header) {
        return false;
    }

    prepare_keystorage_folder(folder);
    snprintf(filename,
             sizeof(filename),
             "%s_%s",
             TL_HEADER_FILENAME_PREFIX,
             _storage_type_to_str(ctx->storage.storage_type));

    return _write_file_data(folder, filename, (uint8_t *)tl_header, sizeof(trust_list_header_t));
}

/******************************************************************************/
bool
read_tl_header_file(tl_context_t *ctx, trust_list_header_t *tl_header) {
    char folder[FILENAME_MAX];
    char filename[FILENAME_MAX];

    if (!tl_header) {
        return false;
    }

    bool result = false;

    prepare_keystorage_folder(folder);
    snprintf(filename,
             sizeof(filename),
             "%s_%s",
             TL_HEADER_FILENAME_PREFIX,
             _storage_type_to_str(ctx->storage.storage_type));

    if (!_file_is_exist(folder, filename)) {
        memset(tl_header, 0xFF, sizeof(trust_list_header_t));

        if (!_write_file_data(folder, filename, (uint8_t *)tl_header, sizeof(trust_list_header_t))) {
            return false;
        }
    } else {
        size_t data_sz;

        if (_read_file_data(folder, filename, (uint8_t *)tl_header, sizeof(trust_list_header_t), &data_sz) &&
            data_sz == sizeof(trust_list_header_t)) {
            result = true;
        }
    }
    return result;
}

/******************************************************************************/
bool
write_tl_key_file(tl_context_t *ctx, size_t key_id, const trust_list_pub_key_t *key) {
    char filename[FILENAME_MAX];
    char folder[FILENAME_MAX];

    prepare_keystorage_folder(folder);
    snprintf(filename,
             sizeof(filename),
             "%s_%s_%u",
             TL_KEY_FILENAME_PREFIX,
             _storage_type_to_str(ctx->storage.storage_type),
             (uint32_t)key_id);

    return _write_file_data(folder, filename, (uint8_t *)key, sizeof(trust_list_pub_key_t));
}

/******************************************************************************/
bool
read_tl_key_file(tl_context_t *ctx, size_t key_id, trust_list_pub_key_t *key) {
    char filename[FILENAME_MAX];
    char folder[FILENAME_MAX];

    if (!key) {
        return false;
    }

    bool result = false;

    prepare_keystorage_folder(folder);
    snprintf(filename,
             sizeof(filename),
             "%s_%s_%u",
             TL_KEY_FILENAME_PREFIX,
             _storage_type_to_str(ctx->storage.storage_type),
             (uint32_t)key_id);

    if (!_file_is_exist(folder, filename)) {
        memset(key, 0xFF, sizeof(trust_list_pub_key_t));

        if (!_write_file_data(folder, filename, (uint8_t *)key, sizeof(trust_list_pub_key_t))) {
            return false;
        }
    } else {
        size_t data_sz;

        if (_read_file_data(folder, filename, (uint8_t *)key, sizeof(trust_list_pub_key_t), &data_sz) &&
            data_sz == sizeof(trust_list_pub_key_t)) {
            result = true;
        }
    }
    return result;
}

/******************************************************************************/
bool
remove_keystorage_tl_header_file(tl_context_t *ctx) {
    char folder[FILENAME_MAX];
    char file_path[FILENAME_MAX];

    prepare_keystorage_folder(folder);
    int res = snprintf(file_path,
                       sizeof(file_path),
                       "%s/%s_%s",
                       folder,
                       TL_HEADER_FILENAME_PREFIX,
                       _storage_type_to_str(ctx->storage.storage_type));

    if (res < 0 || res >= sizeof(file_path) || remove(file_path) < 0) {
        return false;
    }

    return true;
}

/******************************************************************************/
bool
remove_keystorage_tl_key_file(tl_context_t *ctx, tl_key_handle handle) {
    char folder[FILENAME_MAX];
    char file_path[FILENAME_MAX];

    prepare_keystorage_folder(folder);
    int res = snprintf(file_path,
                       sizeof(file_path),
                       "%s/%s_%s_%u",
                       folder,
                       TL_KEY_FILENAME_PREFIX,
                       _storage_type_to_str(ctx->storage.storage_type),
                       (uint32_t)handle);

    if (res < 0 || res >= sizeof(file_path) || remove(file_path) < 0) {
        return false;
    }

    return true;
}

/******************************************************************************/
bool
remove_keystorage_tl_footer_file(tl_context_t *ctx) {
    char folder[FILENAME_MAX];
    char file_path[FILENAME_MAX];

    prepare_keystorage_folder(folder);
    int res = snprintf(file_path,
                       sizeof(file_path),
                       "%s/%s_%s",
                       folder,
                       TL_FOOTER_FILENAME_PREFIX,
                       _storage_type_to_str(ctx->storage.storage_type));

    if (res < 0 || res >= sizeof(file_path) || remove(file_path) < 0) {
        return false;
    }

    return true;
}

/******************************************************************************/
bool
write_tl_footer_file(tl_context_t *ctx, const trust_list_footer_t *footer) {
    char folder[FILENAME_MAX];
    char filename[FILENAME_MAX];

    prepare_keystorage_folder(folder);
    snprintf(filename,
             sizeof(filename),
             "%s_%s",
             TL_FOOTER_FILENAME_PREFIX,
             _storage_type_to_str(ctx->storage.storage_type));

    return _write_file_data(folder, filename, (uint8_t *)footer, sizeof(trust_list_footer_t));
}

/******************************************************************************/
bool
read_tl_footer_file(tl_context_t *ctx, trust_list_footer_t *footer) {
    if (!footer) {
        return false;
    }

    char folder[FILENAME_MAX];
    char filename[FILENAME_MAX];

    bool result = false;

    prepare_keystorage_folder(folder);
    snprintf(filename,
             sizeof(filename),
             "%s_%s",
             TL_FOOTER_FILENAME_PREFIX,
             _storage_type_to_str(ctx->storage.storage_type));

    if (!_file_is_exist(folder, filename)) {
        memset(footer, 0xFF, sizeof(trust_list_footer_t));

        if (!_write_file_data(folder, filename, (uint8_t *)footer, sizeof(trust_list_footer_t))) {
            return false;
        }
    } else {
        size_t data_sz;

        if (_read_file_data(folder, filename, (uint8_t *)footer, sizeof(trust_list_footer_t), &data_sz) &&
            data_sz == sizeof(trust_list_footer_t)) {
            result = true;
        }
    }
    return result;
}
