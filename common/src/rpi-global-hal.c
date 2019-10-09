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
#include <virgil/iot/protocols/sdmp/info-server.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/secbox/secbox.h>
#include <stdlib-config.h>
#include <trust_list-config.h>
#include <update-config.h>
#include "hal/rpi-global-hal.h"
#include "hal/storage/rpi-storage-hal.h"

#include "hal/netif/netif-queue.h"
#include "hal/netif/rpi-udp-broadcast.h"
#include "hal/storage/rpi-file-io.h"

#define NEW_APP_EXTEN ".new"
#define BACKUP_APP_EXTEN ".old"

#define CMD_STR_CPY_TEMPLATE "cp %s %s"
#define CMD_STR_MV_TEMPLATE "mv %s %s"
#define CMD_STR_START_TEMPLATE "%s %s"

static pthread_mutex_t _sleep_lock;
static bool _need_restart = false;

// TODO: Need to use real descriptor, which can be obtain from footer of self image
static vs_firmware_descriptor_t _descriptor;
static bool _is_descriptor_ready = false;

/******************************************************************************/
void
vs_iot_assert(int exp) {
    assert(exp);
}

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
vs_rpi_get_serial(vs_device_serial_t serial) {
    vs_mac_addr_t mac;
    vs_sdmp_mac_addr(0, &mac);

    // TODO: Need to use real serial
    VS_IOT_MEMSET(serial, 0x03, VS_DEVICE_SERIAL_SIZE);
    VS_IOT_MEMCPY(serial, mac.bytes, ETH_ADDR_LEN);
}

/******************************************************************************/
static void
_create_field(uint8_t *dst, const char *src, size_t elem_buf_size) {
    size_t pos;
    size_t len;

    assert(src && *src);
    assert(elem_buf_size);

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
    vs_storage_op_ctx_t op_ctx;
    vs_firmware_descriptor_t desc;

    assert(manufacture_id_str);
    assert(device_type_str);

    vs_rpi_get_storage_impl(&op_ctx.impl);
    assert(op_ctx.impl.deinit);
    op_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;

    op_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_firmware_dir());

    memset(manufacture_id, 0, sizeof(vs_device_manufacture_id_t));
    memset(device_type, 0, sizeof(vs_device_type_t));

    _create_field(manufacture_id, manufacture_id_str, VS_DEVICE_MANUFACTURE_ID_SIZE);
    _create_field(device_type, device_type_str, VS_DEVICE_DEVICE_TYPE_SIZE);

    if (VS_CODE_OK != vs_firmware_load_firmware_descriptor(&op_ctx, manufacture_id, device_type, &desc)) {
        VS_LOG_WARNING("Unable to obtain Firmware's descriptor");
    } else {
        vs_firmware_delete_firmware(&op_ctx, &desc);
    }

    op_ctx.impl.deinit(op_ctx.storage_ctx);
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
static void
_wave_signal_process(int sig, siginfo_t *si, void *context) {
    pthread_mutex_unlock(&_sleep_lock);
}

/******************************************************************************/
void
vs_rpi_hal_sleep_until_stop(void) {
    struct sigaction sigaction_ctx;

    memset(&sigaction_ctx, 0, sizeof(sigaction_ctx));

    // Catch Signals to terminate application correctly
    sigaction_ctx.sa_flags = SA_SIGINFO;
    sigaction_ctx.sa_sigaction = _wave_signal_process;
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
vs_rpi_start(const char *devices_dir,
             const char *app_file,
             vs_mac_addr_t forced_mac_addr,
             vs_storage_op_ctx_t *tl_ctx,
             vs_storage_op_ctx_t *fw_ctx,
             const char *manufacture_id_str,
             const char *device_type_str,
             const uint32_t device_roles,
             bool is_initializer) {
    vs_device_manufacture_id_t manufacture_id;
    vs_device_type_t device_type;
    vs_device_serial_t serial;
    int sz;
    vs_netif_t *netif = NULL;
    vs_netif_t *queued_netif = NULL;
    vs_status_e ret_code;

    vs_logger_init(VS_LOGLEV_DEBUG);

    // Check input variables
    assert(devices_dir);
    assert(app_file);
    assert(manufacture_id_str);
    assert(device_type_str);

    // Print title
    VS_LOG_INFO("\n\n");
    VS_LOG_INFO("--------------------------------------------");
    VS_LOG_INFO("%s app at %s", devices_dir, app_file);
    VS_LOG_INFO("Manufacture ID = \"%s\" , Device type = \"%s\"", manufacture_id_str, device_type_str);
    VS_LOG_INFO("--------------------------------------------\n");

    // Set Manufacture ID
    memset(&manufacture_id, 0, sizeof(manufacture_id));
    sz = strlen(manufacture_id_str);
    if (sz > sizeof(manufacture_id)) {
        sz = sizeof(manufacture_id);
    }
    memcpy((char *)manufacture_id, manufacture_id_str, sz);

    // Se Device type
    memset(&device_type, 0, sizeof(device_type));
    sz = strlen(device_type_str);
    if (sz > sizeof(device_type)) {
        sz = sizeof(device_type);
    }
    memcpy((char *)device_type, device_type_str, sz);

    // Set storage directory
    vs_hal_files_set_dir(devices_dir);

    // Set MAC for emulated device
    vs_hal_files_set_mac(forced_mac_addr.bytes);

    // Prepare TL storage
    vs_rpi_get_storage_impl(&tl_ctx->impl);
    tl_ctx->storage_ctx = vs_rpi_storage_init(vs_rpi_get_trust_list_dir());
    tl_ctx->file_sz_limit = VS_TL_STORAGE_MAX_PART_SIZE;
    ret_code = vs_tl_init(tl_ctx);
    if (!is_initializer && VS_CODE_OK != ret_code) {
        CHECK_RET(false, -1, "Unable to initialize Trust List library");
    }


    // Prepare FW storage
    if (!is_initializer) {
        vs_rpi_get_storage_impl(&fw_ctx->impl);
        fw_ctx->storage_ctx = vs_rpi_storage_init(vs_rpi_get_firmware_dir());
        fw_ctx->file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;
        CHECK_RET(!vs_firmware_init(fw_ctx), VS_CODE_ERR_INCORRECT_ARGUMENT, "Unable to initialize Firmware library");
    }

    // Setup UDP Broadcast as network interface
    vs_hal_netif_udp_bcast_force_mac(forced_mac_addr);

    // Get PLC Network interface
    netif = vs_hal_netif_udp_bcast();

    // Prepare queued network interface
    queued_netif = vs_netif_queued(netif);

    // Initialize SDMP
    vs_rpi_get_serial(serial);
    CHECK_RET(!vs_sdmp_init(queued_netif, manufacture_id, device_type, serial, device_roles),
              VS_CODE_ERR_SDMP_UNKNOWN,
              "Unable to initialize SDMP");

    if (!is_initializer) {
        CHECK_RET(!vs_sdmp_register_service(vs_sdmp_info_server(tl_ctx, fw_ctx)), VS_CODE_ERR_SDMP_UNKNOWN, 0);
        // Send broadcast notification about start of this device
        CHECK_RET(!vs_sdmp_info_start_notification(NULL),
                  VS_CODE_ERR_SDMP_UNKNOWN,
                  "Cannot send broadcast notification about start");
    }

    return VS_CODE_OK;
}

/******************************************************************************/
void
vs_rpi_restart(void) {
    _need_restart = true;
    pthread_mutex_unlock(&_sleep_lock);
}

/******************************************************************************/
int
vs_load_own_firmware_descriptor(const char *manufacture_id_str,
                                const char *device_type_str,
                                vs_storage_op_ctx_t *op_ctx,
                                vs_firmware_descriptor_t *descriptor) {

    assert(descriptor);
    CHECK_NOT_ZERO_RET(descriptor, -1);

    if (!_is_descriptor_ready) {
        vs_firmware_descriptor_t desc;
        vs_device_manufacture_id_t manufacture_id;
        vs_device_type_t device_type;

        memset(&desc, 0, sizeof(vs_firmware_descriptor_t));
        memset(manufacture_id, 0, sizeof(vs_device_manufacture_id_t));
        memset(device_type, 0, sizeof(vs_device_type_t));

        _create_field(manufacture_id, manufacture_id_str, VS_DEVICE_MANUFACTURE_ID_SIZE);
        _create_field(device_type, device_type_str, VS_DEVICE_DEVICE_TYPE_SIZE);

        if (VS_CODE_OK != vs_firmware_load_firmware_descriptor(op_ctx, manufacture_id, device_type, &desc)) {
            VS_LOG_WARNING("Unable to obtain Firmware's descriptor. Use default");
            memset(&_descriptor, 0, sizeof(vs_firmware_descriptor_t));
            memcpy(_descriptor.info.manufacture_id, manufacture_id, VS_DEVICE_MANUFACTURE_ID_SIZE);
            memcpy(_descriptor.info.device_type, device_type, VS_DEVICE_DEVICE_TYPE_SIZE);
        } else {
            memcpy(&_descriptor, &desc, sizeof(vs_firmware_descriptor_t));
        }
        _is_descriptor_ready = true;
    }

    memcpy(descriptor, &_descriptor, sizeof(vs_firmware_descriptor_t));

    return 0;
}
