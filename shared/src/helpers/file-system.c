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
#include <string.h>

#include <dirent.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>

#include "communication/gateway_netif_plc.h"
#include "secbox_impl/file-system.h"
#include <sys/stat.h>

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>

static const char *KEYSTORAGE_DIR = "keystorage";

/******************************************************************************/
#define UNIX_CALL(OPERATION)                                                                                           \
    do {                                                                                                               \
        if (OPERATION) {                                                                                               \
            VS_LOG_ERROR("Unix call " #OPERATION " error. errno = %d (%s)", errno, strerror(errno));                   \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

/******************************************************************************/
void
prepare_keystorage_folder(char *folder) {
    struct passwd *pwd = NULL;
    vs_mac_addr_t mac_addr;
    char *p = folder;

    assert(folder);

    pwd = getpwuid(getuid());

    strcpy(p, pwd->pw_dir);
    p += strlen(p);

    *p++ = '/';

    strcpy(p, KEYSTORAGE_DIR);
    p += strlen(p);

    *p++ = '/';

    vs_hal_netif_plc()->mac_addr(&mac_addr);

    snprintf(p,
             FILENAME_MAX - strlen(folder),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr.bytes[0],
             mac_addr.bytes[1],
             mac_addr.bytes[2],
             mac_addr.bytes[3],
             mac_addr.bytes[4],
             mac_addr.bytes[5]);
}

/******************************************************************************/
bool
write_keystorage_file(const char *folder, const char *file_name, const uint8_t *data, uint16_t data_sz) {
    return write_file(folder, file_name, data, data_sz);
}

/******************************************************************************/
bool
read_keystorage_file(const char *folder, const char *file_name, uint8_t *buf, uint16_t buf_sz, uint16_t *out_sz) {
    return read_file(folder, file_name, buf, buf_sz, out_sz);
}

/******************************************************************************/
static char *
_full_path(const char *basedir, char *basepath) {
    struct passwd *pwd = NULL;
    char *p = NULL;

    assert(basedir);
    assert(*basedir);

    pwd = getpwuid(getuid());

    strcpy(basepath, pwd->pw_dir);
    p = basepath + strlen(basepath);
    *p++ = '/';
    strcpy(p, basedir);

    return basepath;
}

/******************************************************************************/
static bool
init_fio(const char *basepath) {
    DIR *d = NULL;
    char *p = NULL;
    char tmp[FILENAME_MAX];
    size_t len;

    assert(basepath);
    assert(*basepath);

    d = opendir(basepath);

    if (d) {
        closedir(d);
        return true;
    }

    VS_LOG_DEBUG("Create base path %s", basepath);
    len = strlen(basepath);
    memcpy(tmp, basepath, len + 1);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            if (mkdir(basepath, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST) {
                VS_LOG_ERROR("mkdir call for %s path has not been successful. errno = %d (%s)",
                             basepath,
                             errno,
                             strerror(errno));
                goto terminate;
            }
            *p = '/';
        }

    if (mkdir(basepath, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST) {
        VS_LOG_ERROR(
                "mkdir call for %s path has not been successful. errno = %d (%s)", basepath, errno, strerror(errno));
        goto terminate;
    }

    return true;

terminate:

    return false;
}

/******************************************************************************/
bool
write_file(const char *basedir, const char *filename, const void *data, uint16_t data_sz) {
    FILE *fp = NULL;
    bool res = false;
    char filepath[FILENAME_MAX];
    char *p;

    if (!init_fio(_full_path(basedir, filepath))) {
        VS_LOG_ERROR("Unable to access base directory %s", basedir);
        goto terminate;
    }

    p = filepath + strlen(filepath);
    *p++ = '/';
    strcpy(p, filename);
    VS_LOG_DEBUG("Write file '%s', %d bytes", filepath, data_sz);

    fp = fopen(filepath, "wb");

    if (fp) {
        if (1 != fwrite(data, data_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to write %d bytes to the file %s. errno = %d (%s)",
                         data_sz,
                         filepath,
                         errno,
                         strerror(errno));
        }
    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", filepath, errno, strerror(errno));
    }

    res = true;

terminate:

    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
bool
read_file(const char *basedir, const char *filename, uint8_t *data, uint16_t buf_sz, uint16_t *read_sz) {
    FILE *fp = NULL;
    bool res = false;
    char filepath[FILENAME_MAX];
    char *p;

    if (!init_fio(_full_path(basedir, filepath))) {
        VS_LOG_ERROR("Unable to access base directory %s", basedir);
        goto terminate;
    }

    p = filepath + strlen(filepath);
    *p++ = '/';
    strcpy(p, filename);

    fp = fopen(filepath, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, 0L, SEEK_END));
        *read_sz = ftell(fp);
        rewind(fp);

        VS_LOG_DEBUG("Read file '%s', %d bytes", filepath, (int)*read_sz);

        if (!*read_sz) {
            VS_LOG_ERROR("File %s is empty", filepath);
        } else if (buf_sz < *read_sz) {
            VS_LOG_ERROR("File %s size is %d, buffer size %d is not enough", filepath, *read_sz, buf_sz);
        } else if (1 == fread((void *)data, *read_sz, 1, fp)) {
            res = true;
        } else {
            VS_LOG_ERROR("Unable to read %d bytes from %s", *read_sz, filepath);
        }

    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", filepath, errno, strerror(errno));
    }

terminate:

    if (fp) {
        fclose(fp);
    }

    return res;
}

#undef UNIX_CALL

/******************************************************************************/
// bool read_keystorage_file(const char* folder, const char* file_name, uint8_t* out_data, size_t buf_sz, size_t*
// out_sz)
//{
//    if (!folder || !file_name || !out_data)
//        return false;
//
//    bool result = false;
//    *out_sz = 0;
//
//    if (_file_is_exist(folder, file_name)) {
//        if (_read_file_data(folder, file_name, (uint8_t*)out_data, buf_sz, out_sz)) {
//
//            result = true;
//        }
//    }
//    return result;
//}
//
///******************************************************************************/
// bool write_tl_header_file(tl_context_t* ctx, const trust_list_header_t* tl_header)
//{
//    char folder[FILENAME_MAX];
//    char filename[FILENAME_MAX];
//
//    if (!tl_header) {
//        return false;
//    }
//
//    prepare_keystorage_folder(folder);
//    snprintf(filename,
//        sizeof(filename),
//        "%s_%s",
//        TL_HEADER_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type));
//
//    return _write_file_data(folder, filename, (uint8_t*)tl_header, sizeof(trust_list_header_t));
//}

/******************************************************************************/
// bool read_tl_header_file(tl_context_t* ctx, trust_list_header_t* tl_header)
//{
//    char folder[FILENAME_MAX];
//    char filename[FILENAME_MAX];
//
//    if (!tl_header) {
//        return false;
//    }
//
//    bool result = false;
//
//    prepare_keystorage_folder(folder);
//    snprintf(filename,
//        sizeof(filename),
//        "%s_%s",
//        TL_HEADER_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type));
//
//    if (!_file_is_exist(folder, filename)) {
//        memset(tl_header, 0xFF, sizeof(trust_list_header_t));
//
//        if (!_write_file_data(folder, filename, (uint8_t*)tl_header, sizeof(trust_list_header_t))) {
//            return false;
//        }
//    } else {
//        size_t data_sz;
//
//        if (_read_file_data(folder, filename, (uint8_t*)tl_header, sizeof(trust_list_header_t), &data_sz) && data_sz
//        == sizeof(trust_list_header_t)) {
//            result = true;
//        }
//    }
//    return result;
//}

/******************************************************************************/
// bool write_tl_key_file(tl_context_t* ctx, size_t key_id, const trust_list_pub_key_t* key)
//{
//    char filename[FILENAME_MAX];
//    char folder[FILENAME_MAX];
//
//    prepare_keystorage_folder(folder);
//    snprintf(filename,
//        sizeof(filename),
//        "%s_%s_%u",
//        TL_KEY_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type),
//        (uint32_t)key_id);
//
//    return _write_file_data(folder, filename, (uint8_t*)key, sizeof(trust_list_pub_key_t));
//}

/******************************************************************************/
// bool read_tl_key_file(tl_context_t* ctx, size_t key_id, trust_list_pub_key_t* key)
//{
//    char filename[FILENAME_MAX];
//    char folder[FILENAME_MAX];
//
//    if (!key) {
//        return false;
//    }
//
//    bool result = false;
//
//    prepare_keystorage_folder(folder);
//    snprintf(filename,
//        sizeof(filename),
//        "%s_%s_%u",
//        TL_KEY_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type),
//        (uint32_t)key_id);
//
//    if (!_file_is_exist(folder, filename)) {
//        memset(key, 0xFF, sizeof(trust_list_pub_key_t));
//
//        if (!_write_file_data(folder, filename, (uint8_t*)key, sizeof(trust_list_pub_key_t))) {
//            return false;
//        }
//    } else {
//        size_t data_sz;
//
//        if (_read_file_data(folder, filename, (uint8_t*)key, sizeof(trust_list_pub_key_t), &data_sz) && data_sz ==
//        sizeof(trust_list_pub_key_t)) {
//            result = true;
//        }
//    }
//    return result;
//}

/******************************************************************************/
// bool remove_keystorage_tl_header_file(tl_context_t* ctx)
//{
//    char folder[FILENAME_MAX];
//    char file_path[FILENAME_MAX];
//
//    prepare_keystorage_folder(folder);
//    int res = snprintf(file_path,
//        sizeof(file_path),
//        "%s/%s_%s",
//        folder,
//        TL_HEADER_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type));
//
//    if (res < 0 || res >= sizeof(file_path) || remove(file_path) < 0) {
//        return false;
//    }
//
//    return true;
//}
//
///******************************************************************************/
// bool remove_keystorage_tl_key_file(tl_context_t* ctx, tl_key_handle handle)
//{
//    char folder[FILENAME_MAX];
//    char file_path[FILENAME_MAX];
//
//    prepare_keystorage_folder(folder);
//    int res = snprintf(file_path,
//        sizeof(file_path),
//        "%s/%s_%s_%u",
//        folder,
//        TL_KEY_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type),
//        (uint32_t)handle);
//
//    if (res < 0 || res >= sizeof(file_path) || remove(file_path) < 0) {
//        return false;
//    }
//
//    return true;
//}
//
///******************************************************************************/
// bool remove_keystorage_tl_footer_file(tl_context_t* ctx)
//{
//    char folder[FILENAME_MAX];
//    char file_path[FILENAME_MAX];
//
//    prepare_keystorage_folder(folder);
//    int res = snprintf(file_path,
//        sizeof(file_path),
//        "%s/%s_%s",
//        folder,
//        TL_FOOTER_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type));
//
//    if (res < 0 || res >= sizeof(file_path) || remove(file_path) < 0) {
//        return false;
//    }
//
//    return true;
//}
//
///******************************************************************************/
// bool write_tl_footer_file(tl_context_t* ctx, const trust_list_footer_t* footer)
//{
//    char folder[FILENAME_MAX];
//    char filename[FILENAME_MAX];
//
//    prepare_keystorage_folder(folder);
//    snprintf(filename,
//        sizeof(filename),
//        "%s_%s",
//        TL_FOOTER_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type));
//
//    return _write_file_data(folder, filename, (uint8_t*)footer, sizeof(trust_list_footer_t));
//}
//
///******************************************************************************/
// bool read_tl_footer_file(tl_context_t* ctx, trust_list_footer_t* footer)
//{
//    if (!footer) {
//        return false;
//    }
//
//    char folder[FILENAME_MAX];
//    char filename[FILENAME_MAX];
//
//    bool result = false;
//
//    prepare_keystorage_folder(folder);
//    snprintf(filename,
//        sizeof(filename),
//        "%s_%s",
//        TL_FOOTER_FILENAME_PREFIX,
//        _storage_type_to_str(ctx->storage.storage_type));
//
//    if (!_file_is_exist(folder, filename)) {
//        memset(footer, 0xFF, sizeof(trust_list_footer_t));
//
//        if (!_write_file_data(folder, filename, (uint8_t*)footer, sizeof(trust_list_footer_t))) {
//            return false;
//        }
//    } else {
//        size_t data_sz;
//
//        if (_read_file_data(folder, filename, (uint8_t*)footer, sizeof(trust_list_footer_t), &data_sz) && data_sz ==
//        sizeof(trust_list_footer_t)) {
//            result = true;
//        }
//    }
//    return result;
//}
