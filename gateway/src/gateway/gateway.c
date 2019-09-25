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

#include "gateway.h"
#include "message_bin.h"
#include "upd_http_retrieval_thread.h"
#include "event-flags.h"
#include "fldt_implementation.h"
#include "hal/storage/rpi-storage-hal.h"
#include "hal/rpi-global-hal.h"

#include <global-hal.h>
#include <update-config.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp/fldt_private.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>

static gtwy_t _gtwy = {.fw_update_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE,
                       .firmware_mutex = PTHREAD_MUTEX_INITIALIZER,
                       .tl_mutex = PTHREAD_MUTEX_INITIALIZER};


static bool is_threads_started = false;
static pthread_t gateway_starter_thread;

#define MAIN_THREAD_SLEEP_S 2

#if SIMULATOR
static const char _test_message[] = TEST_UPDATE_MESSAGE;
#endif

static pthread_t *message_bin_thread;
static pthread_t *upd_http_retrieval_thread;

extern const vs_update_fw_descriptor_t *
vs_global_hal_get_own_firmware_descriptor(void);
/******************************************************************************/
gtwy_t *
init_gateway_ctx(vs_mac_addr_t *mac_addr) {
    vs_rpi_hal_get_udid(_gtwy.udid_of_device);

    vs_rpi_get_storage_impl(&_gtwy.fw_update_ctx.impl);
    _gtwy.fw_update_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_firmware_dir());

    if (0 != vs_event_group_init(&_gtwy.incoming_data_events)) {
        exit(-1);
    }
    if (0 != vs_event_group_init(&_gtwy.message_bin_events)) {
        exit(-1);
    }
    if (0 != vs_event_group_init(&_gtwy.shared_events)) {
        exit(-1);
    }

    return &_gtwy;
}

/******************************************************************************/
gtwy_t *
get_gateway_ctx(void) {
    return &_gtwy;
}

/*************************************************************************/
static bool
_is_self_firmware_image(vs_firmware_info_t *fw_info) {
    const vs_update_fw_descriptor_t *desc = vs_global_hal_get_own_firmware_descriptor();

    return (0 == VS_IOT_MEMCMP(desc->info.manufacture_id, fw_info->manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == VS_IOT_MEMCMP(desc->info.device_type, fw_info->device_type, DEVICE_TYPE_SIZE));
}

/*************************************************************************/
static int
_cancel_thread(pthread_t *thread) {
    void *res;

    if (0 != pthread_cancel(*thread)) {
        VS_LOG_ERROR("Unable to cancel message_bin_thread");
        return -1;
    }

    if (0 != pthread_join(*thread, &res) || PTHREAD_CANCELED != res) {
        VS_LOG_ERROR("Error during joining to thread");
        return -1;
    } else {
        VS_LOG_INFO("thread canceled");
    }

    return 0;
}

/*************************************************************************/
static void
_restart_app() {

    // Stop message bin thread
    if (0 != _cancel_thread(message_bin_thread)) {
        VS_LOG_ERROR("Unable to cancel message_bin_thread");
        exit(-1);
    }

    // Stop retrieval thread
    if (0 != _cancel_thread(upd_http_retrieval_thread)) {
        VS_LOG_ERROR("Unable to cancel message_bin_thread");
        exit(-1);
    }

    // Destroy sdmp services
    vs_fldt_destroy_server();

    /* Cleanup a mutexes */
    pthread_mutex_destroy(&_gtwy.firmware_mutex);
    pthread_mutex_destroy(&_gtwy.tl_mutex);
    pthread_mutex_destroy(&_gtwy.shared_events.mtx);

    vs_event_group_destroy(&_gtwy.shared_events);
    vs_event_group_destroy(&_gtwy.incoming_data_events);
    vs_event_group_destroy(&_gtwy.message_bin_events);

    vs_rpi_restart();
    pthread_exit(0);
}

/******************************************************************************/
static void *
_gateway_task(void *pvParameters) {
    vs_update_fw_descriptor_t desc;
    vs_update_file_type_t file_type;
    vs_fldt_fw_add_info_t *fw_add_info = (vs_fldt_fw_add_info_t *)file_type.add_info;
    queued_file_t *queued_file;
    vs_firmware_info_t *request;

    message_bin_thread = start_message_bin_thread();
    CHECK_NOT_ZERO_RET(message_bin_thread, (void *)-1);

    upd_http_retrieval_thread = vs_start_upd_http_retrieval_thread();
    CHECK_NOT_ZERO_RET(upd_http_retrieval_thread, (void *)-1);


    while (true) {
        vs_event_group_wait_bits(&_gtwy.incoming_data_events, EID_BITS_ALL, true, false, MAIN_THREAD_SLEEP_S);
        vs_event_group_set_bits(&_gtwy.shared_events, SDMP_INIT_FINITE_BIT);

        while (vs_upd_http_retrieval_get_request(&queued_file)) {
            file_type.file_type_id = queued_file->file_type;
            memset(file_type.add_info, 0, sizeof(file_type.add_info));

            switch (queued_file->file_type) {
            case VS_UPDATE_FIRMWARE:
                if (queued_file->file_type == VS_UPDATE_FIRMWARE && _is_self_firmware_image(&queued_file->fw_info)) {
                    request = &queued_file->fw_info;
                    if (0 == pthread_mutex_lock(&_gtwy.firmware_mutex)) {
                        if (VS_STORAGE_OK == vs_update_load_firmware_descriptor(&_gtwy.fw_update_ctx,
                                                                                request->manufacture_id,
                                                                                request->device_type,
                                                                                &desc) &&
                            VS_STORAGE_OK == vs_update_install_firmware(&_gtwy.fw_update_ctx, &desc)) {
                            (void)pthread_mutex_unlock(&_gtwy.firmware_mutex);

                            _restart_app();
                        }
                        free(queued_file);
                        (void)pthread_mutex_unlock(&_gtwy.firmware_mutex);
                    }
                }

                VS_LOG_DEBUG("Send info about new Firmware over SDMP");

                request = &queued_file->fw_info;

                memcpy(&fw_add_info->manufacture_id, &request->manufacture_id, sizeof(request->manufacture_id));
                memcpy(&fw_add_info->device_type, &request->device_type, sizeof(request->device_type));
                if (vs_fldt_update_server_file_type(&file_type, &_gtwy.fw_update_ctx, true)) {
                    VS_LOG_ERROR("Unable to add new firmware");
                    // TODO :how to process???
                }
                break;

            case VS_UPDATE_TRUST_LIST:
                VS_LOG_DEBUG("Send info about new Trust List over SDMP");

                if (vs_fldt_update_server_file_type(&file_type, NULL, true)) {
                    VS_LOG_ERROR("Unable to add new Trust List");
                    // TODO :how to process???
                }
                break;

            default:
                VS_LOG_ERROR("Unsupported file type %d", queued_file->file_type);
                break;
            }

            free(queued_file);
        }

#if SIMULATOR
        if (_test_message[0] != 0) { //-V547
            VS_LOG_INFO(_test_message);
        }
#endif
    }
    return (void *)0;
}

/******************************************************************************/
void
start_gateway_threads(void) {
    //        void *res;
    if (!is_threads_started) {
        is_threads_started = true;


        if (0 != pthread_create(&gateway_starter_thread, NULL, _gateway_task, NULL)) {
            VS_LOG_ERROR("Error during starting main gateway thread");
            exit(-1);
        }
    }
}
