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
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include "hal/rpi-global-hal.h"
#include "hal/storage/rpi-storage-hal.h"

#include "sdk-impl/netif/netif-queue.h"
#include "sdk-impl/netif/rpi-udp-broadcast.h"
#include "hal/storage/rpi-file-io.h"
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/cloud/cloud.h>
#include <update-config.h>

#define NEW_APP_EXTEN ".new"
#define BACKUP_APP_EXTEN ".old"

#define CMD_STR_CPY_TEMPLATE "cp %s %s"
#define CMD_STR_MV_TEMPLATE "mv %s %s"
#define CMD_STR_START_TEMPLATE "%s %s"

static const char *_tl_dir = "trust_list";
static const char *_firmware_dir = "firmware";
static const char *_slots_dir = "slots";

static pthread_mutex_t _sleep_lock;
static bool _need_restart = false;
static const char *_self_path;
static vs_device_manufacture_id_t _manufacture_id;
static vs_device_type_t _device_type;

/******************************************************************************/
void
vs_impl_msleep(size_t msec) {
    usleep(msec * 1000);
}

/******************************************************************************/
bool
vs_logger_output_hal(const char *buffer) {
    if (!buffer) {
        return false;
    }

    int res = printf("%s", buffer) != 0;
    fflush(stdout);
    return res != 0;
}

/******************************************************************************/
void
vs_rpi_get_serial(vs_device_serial_t serial, vs_mac_addr_t mac) {
    // TODO: Need to use real serial
    VS_IOT_MEMSET(serial, 0x03, VS_DEVICE_SERIAL_SIZE);
    VS_IOT_MEMCPY(serial, mac.bytes, ETH_ADDR_LEN);
}

/******************************************************************************/
void
vs_impl_device_serial(vs_device_serial_t serial_number) {
    memcpy(serial_number, vs_sdmp_device_serial(), VS_DEVICE_SERIAL_SIZE);
}

/******************************************************************************/
void
vs_rpi_create_data_array(uint8_t *dst, const char *src, size_t elem_buf_size) {
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
static void
_delete_bad_firmware(const char *manufacture_id_str, const char *device_type_str) {

    vs_device_manufacture_id_t manufacture_id;
    vs_device_type_t device_type;
    vs_firmware_descriptor_t desc;

    assert(manufacture_id_str);
    assert(device_type_str);

    vs_rpi_create_data_array(manufacture_id, manufacture_id_str, VS_DEVICE_MANUFACTURE_ID_SIZE);
    vs_rpi_create_data_array(device_type, device_type_str, VS_DEVICE_TYPE_SIZE);

    if (VS_CODE_OK != vs_firmware_load_firmware_descriptor(manufacture_id, device_type, &desc)) {
        VS_LOG_WARNING("Unable to obtain Firmware's descriptor");
    } else {
        if (VS_CODE_OK != vs_firmware_delete_firmware(&desc)) {
            VS_LOG_WARNING("Unable to delete bad firmware image");
            return;
        }
    }

    VS_LOG_INFO("Bad firmware has been deleted");
}

/******************************************************************************/
int
vs_rpi_hal_update(const char *manufacture_id_str, const char *device_type_str, int argc, char *argv[]) {
    char old_app[FILENAME_MAX];
    char new_app[FILENAME_MAX];
    char cmd_str[sizeof(new_app) + sizeof(old_app) + 1];

    if (!_need_restart) {
        return 0;
    }

    if (NULL == _self_path) {
        return -1;
    }

    size_t pos;

    VS_LOG_INFO("Try to update app");

    strncpy(new_app, _self_path, sizeof(new_app) - sizeof(NEW_APP_EXTEN));
    strncpy(old_app, _self_path, sizeof(new_app) - sizeof(BACKUP_APP_EXTEN));

    strcat(old_app, BACKUP_APP_EXTEN);
    strcat(new_app, NEW_APP_EXTEN);

    uint32_t args_len = 0;

    for (pos = 1; pos < argc; ++pos) {
        args_len += strlen(argv[pos]);
    }

    // argc == number of necessary spaces + \0 (because of we use argv starting from the 1st cell, not zero cell)
    char copy_args[args_len + argc];
    copy_args[0] = 0;

    for (pos = 1; pos < argc; ++pos) {
        strcat(copy_args, argv[pos]);
        strcat(copy_args, " ");
    }

    // Create backup of current app
    VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_CPY_TEMPLATE, _self_path, old_app);
    if (-1 == system(cmd_str)) {
        VS_LOG_ERROR("Error backup current app. errno = %d (%s)", errno, strerror(errno));

        // restart self
        VS_LOG_INFO("Restart current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, _self_path, copy_args);
        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    // Update current app to new
    VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_MV_TEMPLATE, new_app, _self_path);
    if (-1 == system(cmd_str) || -1 == chmod(_self_path, S_IXUSR | S_IWUSR | S_IRUSR)) {
        VS_LOG_ERROR("Error update app. errno = %d (%s)", errno, strerror(errno));

        // restart self
        VS_LOG_INFO("Restart current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, _self_path, copy_args);
        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    // Start new app
    if (-1 == execv(_self_path, argv)) {
        VS_LOG_ERROR("Error start new app. errno = %d (%s)", errno, strerror(errno));

        // remove the bad stored firmware image
        _delete_bad_firmware(manufacture_id_str, device_type_str);

        // restore current app
        VS_LOG_INFO("Restore current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_MV_TEMPLATE, old_app, _self_path);
        if (-1 == system(cmd_str)) {
            VS_LOG_ERROR("Error restore current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }

        // restart self
        VS_LOG_INFO("Restart current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, _self_path, copy_args);
        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    VS_LOG_ERROR("Something wrong");
    return -1;
}

/******************************************************************************/
static void
_wait_signal_process(int sig, siginfo_t *si, void *context) {
    pthread_mutex_unlock(&_sleep_lock);
}

/******************************************************************************/
void
vs_rpi_hal_sleep_until_stop(void) {
    struct sigaction sigaction_ctx;

    memset(&sigaction_ctx, 0, sizeof(sigaction_ctx));

    // Catch Signals to terminate application correctly
    sigaction_ctx.sa_flags = SA_SIGINFO;
    sigaction_ctx.sa_sigaction = _wait_signal_process;
    sigaction(SIGINT, &sigaction_ctx, NULL);
    sigaction(SIGTERM, &sigaction_ctx, NULL);

    if (0 != pthread_mutex_init(&_sleep_lock, NULL)) {
        VS_LOG_ERROR("Mutex init failed");
        return;
    }

    pthread_mutex_lock(&_sleep_lock);
    pthread_mutex_lock(&_sleep_lock);

    pthread_mutex_destroy(&_sleep_lock);
}

/******************************************************************************/
vs_status_e
vs_rpi_prepare_storage(const char *devices_dir, vs_mac_addr_t device_mac) {
    static char base_dir[FILENAME_MAX] = {0};


    CHECK_NOT_ZERO_RET(devices_dir && devices_dir[0], VS_CODE_ERR_INCORRECT_ARGUMENT);

    if (VS_IOT_SNPRINTF(base_dir,
                        FILENAME_MAX,
                        "%s/%x:%x:%x:%x:%x:%x",
                        devices_dir,
                        device_mac.bytes[0],
                        device_mac.bytes[1],
                        device_mac.bytes[2],
                        device_mac.bytes[3],
                        device_mac.bytes[4],
                        device_mac.bytes[5]) <= 0) {
        return VS_CODE_ERR_TOO_SMALL_BUFFER;
    }

    return vs_hal_files_set_dir(base_dir) ? VS_CODE_OK : VS_CODE_ERR_FILE;
}

/******************************************************************************/
vs_netif_t *
vs_rpi_create_netif_impl(vs_mac_addr_t forced_mac_addr) {
    vs_netif_t *netif = NULL;
    vs_netif_t *queued_netif = NULL;

    // Get Network interface
    netif = vs_hal_netif_udp_bcast(forced_mac_addr);

    // Prepare queued network interface
    queued_netif = vs_netif_queued(netif);

    return queued_netif;
}

/******************************************************************************/
vs_status_e
vs_rpi_create_storage_impl(vs_storage_op_ctx_t *storage_impl, const char *base_dir, size_t file_size_max) {

    CHECK_NOT_ZERO_RET(storage_impl, VS_CODE_ERR_INCORRECT_ARGUMENT);
    CHECK_NOT_ZERO_RET(base_dir, VS_CODE_ERR_INCORRECT_ARGUMENT);

    memset(storage_impl, 0, sizeof(*storage_impl));

    // Prepare TL storage
    storage_impl->impl_func = vs_rpi_storage_impl_func();
    storage_impl->impl_data = vs_rpi_storage_impl_data_init(base_dir);
    storage_impl->file_sz_limit = file_size_max;

    return VS_CODE_OK;
}

/******************************************************************************/
void
vs_rpi_set_app_metainfo(const char *app_file,
                        const vs_device_manufacture_id_t manufacture_id_str,
                        const vs_device_type_t device_type_str) {
    _self_path = app_file;
    memcpy(_manufacture_id, manufacture_id_str, sizeof(_manufacture_id));
    memcpy(_device_type, device_type_str, sizeof(_device_type));
}

/******************************************************************************/
void
vs_rpi_print_title(const char *devices_dir) {
    VS_LOG_INFO("\n\n");
    VS_LOG_INFO("--------------------------------------------");
    VS_LOG_INFO("%s app at %s", devices_dir, _self_path);
    VS_LOG_INFO("Manufacture ID = \"%s\" , Device type = \"%s\"", _manufacture_id, _device_type);
    VS_LOG_INFO("--------------------------------------------\n");
}

/******************************************************************************/
void
vs_rpi_restart(void) {
    _need_restart = true;
    pthread_mutex_unlock(&_sleep_lock);
}

/******************************************************************************/
vs_status_e
vs_load_own_footer(uint8_t *footer, uint16_t footer_sz) {
    FILE *fp = NULL;
    vs_status_e res = VS_CODE_ERR_FILE_READ;
    ssize_t length;

    assert(footer);
    assert(_self_path);

    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_FILE_READ);
    CHECK_NOT_ZERO_RET(_self_path, VS_CODE_ERR_FILE_READ);

    vs_firmware_footer_t *own_footer = (vs_firmware_footer_t *)footer;

    fp = fopen(_self_path, "rb");

    CHECK(fp, "Unable to open file %s. errno = %d (%s)", _self_path, errno, strerror(errno));

    CHECK(0 == fseek(fp, 0, SEEK_END), "Unable to seek file %s. errno = %d (%s)", _self_path, errno, strerror(errno));

    length = ftell(fp);
    CHECK(length > 0, "Unable to get file length %s. errno = %d (%s)", _self_path, errno, strerror(errno));
    CHECK(length > footer_sz, "Wrong self file format");

    CHECK(0 == fseek(fp, length - footer_sz, SEEK_SET),
          "Unable to seek file %s. errno = %d (%s)",
          _self_path,
          errno,
          strerror(errno));

    CHECK(1 == fread((void *)footer, footer_sz, 1, fp),
          "Unable to read file %s. errno = %d (%s)",
          _self_path,
          errno,
          strerror(errno));

    vs_cloud_ntoh_fw_descriptor(&own_footer->descriptor);

    // Simple validation of own descriptor
    if (own_footer->signatures_count != VS_FW_SIGNATURES_QTY ||
        0 != memcmp(own_footer->descriptor.info.device_type, _device_type, sizeof(vs_device_type_t)) ||
        0 != memcmp(own_footer->descriptor.info.manufacture_id, _manufacture_id, sizeof(vs_device_manufacture_id_t))) {
        VS_LOG_ERROR("Bad own descriptor!!!! Application aborted");
        exit(-1);
    }

    res = VS_CODE_OK;

terminate:
    if (fp) {
        fclose(fp);
    }

    return res;
}

/******************************************************************************/
vs_status_e
vs_firmware_get_own_firmware_footer_hal(void *footer, size_t footer_sz) {
    assert(footer);
    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return vs_load_own_footer(footer, footer_sz);
}

/******************************************************************************/
const char *
vs_rpi_trustlist_dir(void) {
    return _tl_dir;
}

/******************************************************************************/
const char *
vs_rpi_firmware_dir(void) {
    return _firmware_dir;
}

/******************************************************************************/
const char *
vs_rpi_slots_dir(void) {
    return _slots_dir;
}

/******************************************************************************/
