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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <virgil/iot/hsm/hsm_structs.h>
#include <virgil/iot/hsm/hsm_errors.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/logger/helpers.h>

static char base_dir[FILENAME_MAX] = {0};
static const char *directory = "slots";
static bool initialized = false;

#define CHECK_SNPRINTF(BUF, FORMAT, ...)                                                                               \
    do {                                                                                                               \
        int snprintf_res;                                                                                              \
        if ((snprintf_res = snprintf((BUF), sizeof(BUF), (FORMAT), ##__VA_ARGS__)) <= 0) {                             \
            VS_LOG_ERROR("snprintf error result %d. errno = %d (%s)", snprintf_res, errno, strerror(errno));           \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

#define UNIX_CALL(OPERATION)                                                                                           \
    do {                                                                                                               \
        if (OPERATION) {                                                                                               \
            VS_LOG_ERROR("Unix call " #OPERATION " error. errno = %d (%s)", errno, strerror(errno));                   \
            goto terminate;                                                                                            \
        }                                                                                                              \
    } while (0)

/******************************************************************************/
static bool
_init_fio(void) {
    struct passwd *pwd = NULL;
    char tmp[FILENAME_MAX];
    char *p = NULL;
    size_t len;

    pwd = getpwuid(getuid());
    CHECK_SNPRINTF(base_dir, "%s/%s", pwd->pw_dir, directory);

    VS_LOG_DEBUG("Base directory for slots : %s", base_dir);

    strcpy(tmp, base_dir);
    len = strlen(tmp);

    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST) {
                VS_LOG_ERROR(
                        "mkdir call for %s path has not been successful. errno = %d (%s)", tmp, errno, strerror(errno));
                goto terminate;
            }
            *p = '/';
        }

    if (mkdir(tmp, S_IRWXU | S_IRWXG | S_IRWXO) && errno != EEXIST) {
        VS_LOG_ERROR("mkdir call for %s path has not been successful. errno = %d (%s)", tmp, errno, strerror(errno));
        goto terminate;
    }

    initialized = true;

terminate:

    return initialized;
}

/******************************************************************************/
static bool
_write_file_data(const char *file_name, const void *data, uint16_t data_sz) {
    char file_path[FILENAME_MAX];
    DIR *d = NULL;
    FILE *fp = NULL;
    bool res = false;

    NOT_ZERO(file_name);
    NOT_ZERO(data);
    NOT_ZERO(data_sz);

    if (!initialized && !_init_fio()) {
        VS_LOG_ERROR("Unable to initialize file I/O operations");
        goto terminate;
    }

    d = opendir(base_dir);

    if (d) {
        closedir(d);
    } else {
        VS_LOG_ERROR("Unable to open previously created directory %s", base_dir);
        goto terminate;
    }

    if (snprintf(file_path, sizeof(file_path), "%s/%s", base_dir, file_name) < 0) {
        return false;
    }
    VS_LOG_DEBUG("Write file '%s', %d bytes", file_path, data_sz);

    fp = fopen(file_path, "wb");

    if (fp) {
        if (1 != fwrite(data, data_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to write %d bytes to the file %s. errno = %d (%s)",
                         data_sz,
                         file_path,
                         errno,
                         strerror(errno));
        }
    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", file_path, errno, strerror(errno));
    }

    res = true;

terminate:

    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
static bool
_read_file_data(const char *file_name, uint8_t *data, uint16_t buf_sz, uint16_t *read_sz) {
    char file_path[FILENAME_MAX];
    DIR *d = NULL;
    FILE *fp = NULL;
    bool res = false;

    NOT_ZERO(file_name);
    NOT_ZERO(data);
    NOT_ZERO(read_sz);

    if (!initialized && !_init_fio()) {
        VS_LOG_ERROR("Unable to initialize file I/O operations");
        goto terminate;
    }
    d = opendir(base_dir);

    if (d) {
        closedir(d);
    } else {
        VS_LOG_ERROR("Unable to open previously created directory %s", base_dir);
        goto terminate;
    }
    if (snprintf(file_path, FILENAME_MAX, "%s/%s", base_dir, file_name) < 0) {
        return false;
    }

    fp = fopen(file_path, "rb");

    if (fp) {
        UNIX_CALL(fseek(fp, 0L, SEEK_END));
        *read_sz = ftell(fp);
        rewind(fp);

        VS_LOG_DEBUG("Read file '%s', %d bytes", file_path, (int)*read_sz);

        if (!*read_sz) {
            VS_LOG_ERROR("File %s is empty", file_path);
        } else if (buf_sz < *read_sz) {
            VS_LOG_ERROR("File %s size is %d, buffer size %d is not enough", file_path, *read_sz, buf_sz);
        } else if (1 == fread((void *)data, *read_sz, 1, fp)) {
            res = true;
        } else {
            VS_LOG_ERROR("Unable to read %d bytes from %s", *read_sz, file_path);
        }

    } else {
        VS_LOG_ERROR("Unable to open file %s. errno = %d (%s)", file_path, errno, strerror(errno));
    }

terminate:

    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
const char *
get_slot_name(vs_iot_hsm_slot_e slot) {
    switch (slot) {
    case VS_KEY_SLOT_STD_OTP_0:
        return "STD_OTP_0";
    case VS_KEY_SLOT_STD_OTP_1:
        return "STD_OTP_1";
    case VS_KEY_SLOT_STD_OTP_2:
        return "STD_OTP_2";
    case VS_KEY_SLOT_STD_OTP_3:
        return "STD_OTP_3";
    case VS_KEY_SLOT_STD_OTP_4:
        return "STD_OTP_4";
    case VS_KEY_SLOT_STD_OTP_5:
        return "STD_OTP_5";
    case VS_KEY_SLOT_STD_OTP_6:
        return "STD_OTP_6";
    case VS_KEY_SLOT_STD_OTP_7:
        return "STD_OTP_7";
    case VS_KEY_SLOT_STD_OTP_8:
        return "STD_OTP_8";
    case VS_KEY_SLOT_STD_OTP_9:
        return "STD_OTP_9";
    case VS_KEY_SLOT_STD_OTP_10:
        return "STD_OTP_10";
    case VS_KEY_SLOT_STD_OTP_11:
        return "STD_OTP_11";
    case VS_KEY_SLOT_STD_OTP_12:
        return "STD_OTP_12";
    case VS_KEY_SLOT_STD_OTP_13:
        return "STD_OTP_13";
    case VS_KEY_SLOT_STD_OTP_14:
        return "STD_OTP_14";
    case VS_KEY_SLOT_EXT_OTP_0:
        return "EXT_OTP_0";
    case VS_KEY_SLOT_STD_MTP_0:
        return "STD_MTP_0";
    case VS_KEY_SLOT_STD_MTP_1:
        return "STD_MTP_1";
    case VS_KEY_SLOT_STD_MTP_2:
        return "STD_MTP_2";
    case VS_KEY_SLOT_STD_MTP_3:
        return "STD_MTP_3";
    case VS_KEY_SLOT_STD_MTP_4:
        return "STD_MTP_4";
    case VS_KEY_SLOT_STD_MTP_5:
        return "STD_MTP_5";
    case VS_KEY_SLOT_STD_MTP_6:
        return "STD_MTP_6";
    case VS_KEY_SLOT_STD_MTP_7:
        return "STD_MTP_7";
    case VS_KEY_SLOT_STD_MTP_8:
        return "STD_MTP_8";
    case VS_KEY_SLOT_STD_MTP_9:
        return "STD_MTP_9";
    case VS_KEY_SLOT_STD_MTP_10:
        return "STD_MTP_10";
    case VS_KEY_SLOT_STD_MTP_11:
        return "STD_MTP_11";
    case VS_KEY_SLOT_STD_MTP_12:
        return "STD_MTP_12";
    case VS_KEY_SLOT_STD_MTP_13:
        return "STD_MTP_13";
    case VS_KEY_SLOT_STD_MTP_14:
        return "STD_MTP_14";
    case VS_KEY_SLOT_EXT_MTP_0:
        return "EXT_MTP_0";
    case VS_KEY_SLOT_STD_TMP_0:
        return "STD_TMP_0";
    case VS_KEY_SLOT_STD_TMP_1:
        return "STD_TMP_1";
    case VS_KEY_SLOT_STD_TMP_2:
        return "STD_TMP_2";
    case VS_KEY_SLOT_STD_TMP_3:
        return "STD_TMP_3";
    case VS_KEY_SLOT_STD_TMP_4:
        return "STD_TMP_4";
    case VS_KEY_SLOT_STD_TMP_5:
        return "STD_TMP_5";
    case VS_KEY_SLOT_STD_TMP_6:
        return "STD_TMP_6";
    case VS_KEY_SLOT_EXT_TMP_0:
        return "EXT_TMP_0";

    default:
        assert(false && "Unsupported slot");
        return NULL;
    }
}
#undef UNIX_CALL
#undef CHECK_SNPRINTF

/********************************************************************************/
int
vs_hsm_slot_save(vs_iot_hsm_slot_e slot, const uint8_t *data, uint16_t data_sz) {
    return _write_file_data(get_slot_name(slot), data, data_sz) ? VS_HSM_ERR_OK : VS_HSM_ERR_FILE_IO;
}

/********************************************************************************/
int
vs_hsm_slot_load(vs_iot_hsm_slot_e slot, uint8_t *data, uint16_t buf_sz, uint16_t *out_sz) {
    return _read_file_data(get_slot_name(slot), data, buf_sz, out_sz) ? VS_HSM_ERR_OK : VS_HSM_ERR_FILE_IO;
}
