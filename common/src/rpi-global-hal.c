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
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/protocols/sdmp.h>
#include <stdlib-config.h>
#include "hal/rpi-global-hal.h"

#include "hal/netif/netif-queue.h"
#include "hal/netif/rpi-plc-sim.h"
#include "hal/netif/rpi-udp-broadcast.h"
#include "hal/storage/rpi-file-io.h"

#define NEW_APP_EXTEN ".new"
#define BACKUP_APP_EXTEN ".old"

#define CMD_STR_CPY_TEMPLATE "cp %s %s"
#define CMD_STR_MV_TEMPLATE "mv %s %s"
#define CMD_STR_START_TEMPLATE "%s %s"

static pthread_mutex_t _sleep_lock;

/******************************************************************************/
void
vs_iot_assert(int exp) {
    assert(exp);
}

/******************************************************************************/
void
vs_global_hal_msleep(size_t msec) {
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
vs_rpi_hal_get_udid(uint8_t *udid) {
    vs_mac_addr_t mac;
    vs_sdmp_mac_addr(0, &mac);

    // TODO: Need to use real serial
    VS_IOT_MEMCPY(udid, mac.bytes, ETH_ADDR_LEN);
    VS_IOT_MEMSET(&udid[ETH_ADDR_LEN], 0x03, 32 - ETH_ADDR_LEN);
}

/******************************************************************************/
int
vs_rpi_hal_update(int argc, char *argv[]) {
    char old_app[FILENAME_MAX];
    char new_app[FILENAME_MAX];
    char cmd_str[sizeof(new_app) + sizeof(old_app) + 1];
    char *self_path = argv[0];

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
int
vs_rpi_start(const char *devices_dir, struct in_addr plc_sim_addr, vs_mac_addr_t forced_mac_addr) {
    const vs_netif_t *netif;

    vs_logger_init(VS_LOGLEV_DEBUG);

    assert(devices_dir);

    // Set storage directory
    vs_hal_files_set_dir(devices_dir);

    // Set MAC for emulated device
    vs_hal_files_set_mac(forced_mac_addr.bytes);

    // Prepare TL storage
    vs_tl_init_storage();

    // vs_fldt_init(&forced_mac_addr);

    if (plc_sim_addr.s_addr == htonl(INADDR_ANY)) {
        // Setup UDP Broadcast as network interface
        vs_hal_netif_udp_bcast_force_mac(forced_mac_addr);

        // Get PLC Network interface
        netif = vs_hal_netif_udp_bcast();
    } else {
        // Setup PLC simulator as network interface
        vs_hal_netif_plc_force_mac(forced_mac_addr);

        // Set IP of PLC simulator
        vs_plc_sim_set_ip(plc_sim_addr);

        // Get PLC Network interface
        netif = vs_hal_netif_plc();
    }

    // Initialize SDMP
    CHECK_RET(!vs_sdmp_init(vs_netif_queued(netif)), -1, "Unable to initialize SDMP");

    return 0;
}

/******************************************************************************/