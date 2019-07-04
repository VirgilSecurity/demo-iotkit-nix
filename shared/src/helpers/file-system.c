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

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "communication/gateway_netif_plc.h"
#include "secbox_impl/file-system.h"
#include <sys/stat.h>
#include <virgil/iot/protocols/sdmp.h>

/******************************************************************************/
bool
vs_file_is_exist(const char *folder, const char *file_name) {
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
int
vs_mkdir_recursive(const char *dir) {
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
bool
vs_write_file_data(const char *folder, const char *file_name, const uint8_t *data, size_t data_sz) {
    if (!folder || !file_name || !data)
        return false;

    DIR *d;
    d = opendir(folder);

    if (d) {
        closedir(d);
    } else {
        if (-1 == vs_mkdir_recursive(folder)) {
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
vs_read_file_data(const char *folder, const char *file_name, const uint8_t *data, size_t buf_sz, size_t *data_sz) {
    if (!folder || !file_name || !data)
        return false;

    bool result = false;

    char file_path[FILENAME_MAX];
    snprintf(file_path, FILENAME_MAX, "%s/%s", folder, file_name);

    FILE *fp = fopen(file_path, "rb");
    if (fp) {
        if (1 == fread((void *)data, (size_t)buf_sz, 1, fp)) {
            *data_sz = (size_t)buf_sz;
            result = true;
        }

        fclose(fp);
    }
    return result;
}

/******************************************************************************/
// static const char*
//_storage_type_to_str(size_t storage_type)
//{
//    switch (storage_type) {
//    case TL_STORAGE_TYPE_STATIC:
//        return "stat";
//    case TL_STORAGE_TYPE_DYNAMIC:
//        return "dyn";
//    case TL_STORAGE_TYPE_TMP:
//        return "tmp";
//    default:
//        break;
//    }
//    return "";
//}

/******************************************************************************/
void
prepare_keystorage_folder(char folder[FILENAME_MAX]) {

    vs_mac_addr_t mac_addr;

    vs_hal_netif_plc()->mac_addr(&mac_addr);

    snprintf(folder,
             FILENAME_MAX,
             "%s/%02x_%02x_%02x_%02x_%02x_%02x",
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
    return vs_write_file_data(folder, file_name, data, data_sz);
}

/******************************************************************************/
bool
read_keystorage_file(const char *folder, const char *file_name, uint8_t *out_data, size_t buf_sz, size_t *out_sz) {
    if (!folder || !file_name || !out_data)
        return false;

    bool result = false;
    *out_sz = 0;

    if (vs_file_is_exist(folder, file_name)) {
        if (vs_read_file_data(folder, file_name, (uint8_t *)out_data, buf_sz, out_sz)) {

            result = true;
        }
    }
    return result;
}

/******************************************************************************/