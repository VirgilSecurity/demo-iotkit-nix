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
#include "sdk-impl/storage/storage-nix-impl.h"

#include "sdk-impl/netif/netif-queue.h"
#include "sdk-impl/netif/netif-udp-broadcast.h"
#include "helpers/file-io.h"

#define NEW_APP_EXTEN ".new"
#define BACKUP_APP_EXTEN ".old"

#define CMD_STR_CPY_TEMPLATE "cp %s %s"
#define CMD_STR_MV_TEMPLATE "mv %s %s"
#define CMD_STR_START_TEMPLATE "%s %s"

/******************************************************************************/
void
vs_impl_msleep(size_t msec) {
    usleep(msec * 1000);
}

/******************************************************************************/
void
vs_impl_device_serial(vs_device_serial_t serial_number) {
    memcpy(serial_number, vs_sdmp_device_serial(), VS_DEVICE_SERIAL_SIZE);
}

/******************************************************************************/
static void
_delete_bad_firmware(const char *manufacture_id_str, const char *device_type_str) {

    //    vs_device_manufacture_id_t manufacture_id;
    //    vs_device_type_t device_type;
    //    vs_storage_op_ctx_t op_ctx;
    //    vs_firmware_descriptor_t desc;
    //
    //    assert(manufacture_id_str);
    //    assert(device_type_str);
    //
    //    op_ctx.impl_func = vs_rpi_storage_impl_func();
    //    assert(op_ctx.impl_func.deinit);
    //    op_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;
    //
    //    op_ctx.impl_data = vs_rpi_storage_impl_data_init(vs_rpi_get_firmware_dir());
    //
    //    _create_field(manufacture_id, manufacture_id_str, VS_DEVICE_MANUFACTURE_ID_SIZE);
    //    _create_field(device_type, device_type_str, VS_DEVICE_TYPE_SIZE);
    //
    //    if (VS_CODE_OK != vs_firmware_load_firmware_descriptor(&op_ctx, manufacture_id, device_type, &desc)) {
    //        VS_LOG_WARNING("Unable to obtain Firmware's descriptor");
    //    } else {
    //        vs_firmware_delete_firmware(&op_ctx, &desc);
    //    }
    //
    //    op_ctx.impl_func.deinit(op_ctx.impl_data);
    //    VS_LOG_INFO("Bad firmware has been deleted");
}

/******************************************************************************/
int
vs_rpi_hal_update(const char *manufacture_id_str, const char *device_type_str, int argc, char *argv[]) {
    char old_app[FILENAME_MAX];
    char new_app[FILENAME_MAX];
    char cmd_str[sizeof(new_app) + sizeof(old_app) + 1];

    //    if (!_need_restart) {
    //        return 0;
    //    }

    if (NULL == self_path) {
        return -1;
    }

    size_t pos;

    VS_LOG_INFO("Try to update app");

    strncpy(new_app, self_path, sizeof(new_app) - sizeof(NEW_APP_EXTEN));
    strncpy(old_app, self_path, sizeof(new_app) - sizeof(BACKUP_APP_EXTEN));

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
    VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_CPY_TEMPLATE, self_path, old_app);
    if (-1 == system(cmd_str)) {
        VS_LOG_ERROR("Error backup current app. errno = %d (%s)", errno, strerror(errno));

        // restart self
        VS_LOG_INFO("Restart current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, self_path, copy_args);
        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    // Update current app to new
    VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_MV_TEMPLATE, new_app, self_path);
    if (-1 == system(cmd_str) || -1 == chmod(self_path, S_IXUSR | S_IWUSR | S_IRUSR)) {
        VS_LOG_ERROR("Error update app. errno = %d (%s)", errno, strerror(errno));

        // restart self
        VS_LOG_INFO("Restart current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, self_path, copy_args);
        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    // Start new app
    if (-1 == execv(self_path, argv)) {
        VS_LOG_ERROR("Error start new app. errno = %d (%s)", errno, strerror(errno));

        // remove the bad stored firmware image
        _delete_bad_firmware(manufacture_id_str, device_type_str);

        // restore current app
        VS_LOG_INFO("Restore current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_MV_TEMPLATE, old_app, self_path);
        if (-1 == system(cmd_str)) {
            VS_LOG_ERROR("Error restore current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }

        // restart self
        VS_LOG_INFO("Restart current app");
        VS_IOT_SNPRINTF(cmd_str, sizeof(cmd_str), CMD_STR_START_TEMPLATE, self_path, copy_args);
        if (-1 == execl("/bin/bash", "/bin/bash", "-c", cmd_str, NULL)) {
            VS_LOG_ERROR("Error restart current app. errno = %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    VS_LOG_ERROR("Something wrong");
    return -1;
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

// static void
//_ntoh_fw_desdcriptor(vs_firmware_descriptor_t *desc) {
//    desc->chunk_size = ntohs(desc->chunk_size);
//    desc->app_size = ntohl(desc->app_size);
//    desc->firmware_length = ntohl(desc->firmware_length);
//    desc->info.version.timestamp = ntohl(desc->info.version.timestamp);
//}

/******************************************************************************/
vs_status_e
vs_load_own_footer(uint8_t *footer, uint16_t footer_sz) {
    //    FILE *fp = NULL;
    vs_status_e res = VS_CODE_ERR_FILE_READ;
    //    ssize_t length;
    //
    //    assert(footer);
    //    assert(self_path);
    //
    //    CHECK_NOT_ZERO_RET(footer, VS_CODE_ERR_FILE_READ);
    //    CHECK_NOT_ZERO_RET(self_path, VS_CODE_ERR_FILE_READ);
    //
    //    vs_firmware_footer_t *own_footer = (vs_firmware_footer_t *)footer;
    //
    //    fp = fopen(self_path, "rb");
    //
    //    CHECK(fp, "Unable to open file %s. errno = %d (%s)", self_path, errno, strerror(errno));
    //
    //    CHECK(0 == fseek(fp, 0, SEEK_END), "Unable to seek file %s. errno = %d (%s)", self_path, errno,
    //    strerror(errno));
    //
    //    length = ftell(fp);
    //    CHECK(length > 0, "Unable to get file length %s. errno = %d (%s)", self_path, errno, strerror(errno));
    //    CHECK(length > footer_sz, "Wrong self file format");
    //
    //    CHECK(0 == fseek(fp, length - footer_sz, SEEK_SET),
    //          "Unable to seek file %s. errno = %d (%s)",
    //          self_path,
    //          errno,
    //          strerror(errno));
    //
    //    CHECK(1 == fread((void *)footer, footer_sz, 1, fp),
    //          "Unable to read file %s. errno = %d (%s)",
    //          self_path,
    //          errno,
    //          strerror(errno));
    //    _ntoh_fw_desdcriptor(&own_footer->descriptor);
    //
    //    // Simple validation of own descriptor
    //    if (own_footer->signatures_count != VS_FW_SIGNATURES_QTY ||
    //        0 != memcmp(own_footer->descriptor.info.device_type, _device_type, sizeof(vs_device_type_t)) ||
    //        0 != memcmp(own_footer->descriptor.info.manufacture_id, _manufacture_id,
    //        sizeof(vs_device_manufacture_id_t))) { VS_LOG_ERROR("Bad own descriptor!!!! Application aborted");
    //        exit(-1);
    //    }
    //
    //    res = VS_CODE_OK;
    //
    // terminate:
    //    if (fp) {
    //        fclose(fp);
    //    }

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
