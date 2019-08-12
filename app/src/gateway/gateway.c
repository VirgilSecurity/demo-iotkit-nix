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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#include "platform/platform_os.h"
#include "gateway.h"
#include "gateway_macro.h"
#include "message_bin.h"
#include "upd_http_retrieval_thread.h"
#include "test_update_thread.h"
#include "event_group_bit_flags.h"
#include "gateway_hal.h"

#include <global-hal.h>
#include <virgil/iot/logger/logger.h>

static gtwy_t _gtwy;

static bool is_threads_started = false;
static xTaskHandle gateway_starter_thread;
static const uint16_t starter_thread_stack_size = 10 * 1024;

#if SIMULATOR
static const char _test_message[] = TEST_UPDATE_MESSAGE;
#endif

/******************************************************************************/
gtwy_t *
init_gateway_ctx(vs_mac_addr_t *mac_addr) {
    memset(&_gtwy, 0x00, sizeof(_gtwy));

    vs_gateway_hal_get_udid(_gtwy.udid_of_device);

    _gtwy.shared_event_group = xEventGroupCreate();
    _gtwy.incoming_data_event_group = xEventGroupCreate();
    _gtwy.firmware_event_group = xEventGroupCreate();

    _gtwy.firmware_semaphore = xSemaphoreCreateMutex();
    _gtwy.tl_semaphore = xSemaphoreCreateMutex();

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
    const vs_firmware_descriptor_t *desc = vs_global_hal_get_own_firmware_descriptor();

    return (0 == VS_IOT_MEMCMP(desc->info.manufacture_id, fw_info->manufacture_id, MANUFACTURE_ID_SIZE) &&
            0 == VS_IOT_MEMCMP(desc->info.device_type, fw_info->device_type, DEVICE_TYPE_SIZE));
}

/*************************************************************************/
static void
_restart_app() {
    is_try_to_update = true;

    vTaskEndScheduler();
    while (1)
        ;
}

/******************************************************************************/
static void
_gateway_task(void *pvParameters) {
    vs_firmware_info_t *request;
    vs_firmware_descriptor_t desc;

#if SIMULATOR && SIM_FETCH_FIRMWARE
    start_sim_fetch_thread();
#else
    start_message_bin_thread();
#endif
    start_upd_http_retrieval_thread();

    while (true) {
        int32_t thread_sleep = 3000 / portTICK_PERIOD_MS; //-V501
        // TODO: Main loop will be here
        xEventGroupWaitBits(_gtwy.incoming_data_event_group, EID_BITS_ALL, pdTRUE, pdFALSE, thread_sleep);

        while (upd_http_retrieval_get_request(&request)) {
            if (_is_self_firmware_image(request)) {
                if (VS_UPDATE_ERR_OK ==
                    vs_update_load_firmware_descriptor(request->manufacture_id, request->device_type, &desc) &&
                    VS_UPDATE_ERR_OK == vs_update_install_firmware(&desc)) {
                    _restart_app();
                }
            } else {
                VS_LOG_DEBUG("Send info about new Firmware over SDMP");
            }

            vPortFree(request);
        }

#if SIMULATOR
        if (_test_message[0] != 0) {
            VS_LOG_INFO(_test_message);
        }
#endif
    }
}

/******************************************************************************/
void
start_gateway_threads(void) {
    if (!is_threads_started) {
        is_threads_started = true;
        xTaskCreate(_gateway_task, "gateway_task", starter_thread_stack_size, 0, OS_PRIO_2, &gateway_starter_thread);
        vTaskStartScheduler();
    }
}
