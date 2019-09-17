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

#include "upd_http_retrieval_thread.h"
#include "message_bin.h"
#include "gateway.h"
#include <threads/event-group-bits.h>
#include "event-flags.h"

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/logger/logger.h>

static pthread_t upd_retrieval_thread;

// static const uint16_t upd_retrieval_stack = 10 * 1024;

static bool is_retrieval_started;

#define FWDIST_QUEUE_SZ 10
// xQueueHandle *fwdist_event_queue;

/*************************************************************************/
static void
_sw_retrieval_mb_notify(gtwy_t *gtwy, upd_request_t *request) {
    vs_cloud_firmware_header_t header;
    vs_firmware_info_t *fw_info = NULL;
    int res;
    // It should be immediately available given that this starts first
    if (0 == pthread_mutex_lock(&gtwy->firmware_mutex)) {
        VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got firmware semaphore");

        VS_LOG_DEBUG("[MB_NOTIFY]: Fetch new firmware from URL %s", request->upd_file_url);

        res = vs_cloud_fetch_and_store_fw_file(&get_gateway_ctx()->fw_update_ctx, request->upd_file_url, &header);
        if (VS_CLOUD_ERR_OK == res) {
            VS_LOG_DEBUG("[MB_NOTIFY]:FW image stored succesfully");

            res = vs_update_verify_firmware(&get_gateway_ctx()->fw_update_ctx, &header.descriptor);
            if (VS_STORAGE_OK == res) {

                VS_LOG_DEBUG("[MB_NOTIFY]:FW Successful fetched");

                fw_info = (vs_firmware_info_t *)malloc(sizeof(vs_firmware_info_t));
                VS_IOT_MEMCPY(fw_info, &header.descriptor.info, sizeof(vs_firmware_info_t));

                //            if (pdTRUE != xQueueSendToBack(*fwdist_event_queue, &fw_info, OS_NO_WAIT)) {
                free(fw_info);
                //                VS_LOG_ERROR("[MB] Failed to send fw info to output processing!!!");
                //            }

            } else {
                VS_LOG_DEBUG("[MB_NOTIFY]:Error verify firmware image\r\n");
                vs_update_delete_firmware(&get_gateway_ctx()->fw_update_ctx, &header.descriptor);
            }

        } else {
            VS_LOG_DEBUG("[MB_NOTIFY]:Error fetch new firmware\r\n");
        }
    }

    (void)pthread_mutex_unlock(&gtwy->firmware_mutex);
    VS_LOG_DEBUG("[MB_NOTIFY]:Firmware semaphore freed");

    // This thread needs to be signaled by the off chance that there was a powerloss
    vs_event_group_set_bits(&gtwy->message_bin_events, NEW_FIRMWARE_HTTP_BIT);
    free(request);
}

/*************************************************************************/
static void
_tl_retrieval_mb_notify(gtwy_t *gtwy, upd_request_t *request) {
    if (0 == pthread_mutex_lock(&gtwy->tl_mutex)) {
        VS_LOG_DEBUG("[MB_NOTIFY]:In while loop and got TL semaphore\r\n");

        if (VS_CLOUD_ERR_OK == vs_cloud_fetch_and_store_tl(request->upd_file_url)) {
            VS_LOG_DEBUG("[MB_NOTIFY]:TL Successful fetched\r\n");
            // TODO : notify main thread about new trust list (like for FW above)

        } else {
            VS_LOG_DEBUG("[MB_NOTIFY]:Error fetch new TL\r\n");
        }
    }

    (void)pthread_mutex_unlock(&gtwy->tl_mutex);
    VS_LOG_DEBUG("[MB_NOTIFY]:TL semaphore freed\r\n");
    free(request);
}

/*************************************************************************/
static void *
_upd_http_retrieval_task(void *pvParameters) {
    gtwy_t *gtwy = get_gateway_ctx();

    // Wait for the sdmp stack and services to be up before looking for new firmware
    vs_event_group_wait_bits(&gtwy->shared_events, SDMP_INIT_FINITE_BIT, false, true, VS_EVENT_GROUP_WAIT_INFINITE);

    VS_LOG_DEBUG("vs_upd_http_retrieval thread started");

    while (1) {
        upd_request_t *request;

        vs_event_group_wait_bits(
                &gtwy->message_bin_events, MSG_BIN_RECEIVE_BIT, true, true, VS_EVENT_GROUP_WAIT_INFINITE);

        VS_LOG_DEBUG("vs_upd_http_retrieval thread resume");

        while (message_bin_get_request(&request)) {
            if (MSG_BIN_UPD_TYPE_FW == request->upd_type) {
                _sw_retrieval_mb_notify(gtwy, request);
            } else if (MSG_BIN_UPD_TYPE_TL == request->upd_type) {
                _tl_retrieval_mb_notify(gtwy, request);
            } else {
                free(request);
            }
        }
    }
}

/*************************************************************************/
pthread_t *
vs_start_upd_http_retrieval_thread(void) {
    if (!is_retrieval_started) {
        //        fwdist_event_queue = (xQueueHandle *)pvPortMalloc(sizeof(xQueueHandle));
        //        CHECK_NOT_ZERO_RET(fwdist_event_queue, NULL);
        //        *fwdist_event_queue = xQueueCreate(FWDIST_QUEUE_SZ, sizeof(vs_firmware_info_t *));
        is_retrieval_started = (0 == pthread_create(&upd_retrieval_thread, NULL, _upd_http_retrieval_task, NULL));
        if (!is_retrieval_started) {
            return NULL;
        }
    }
    return &upd_retrieval_thread;
}

/*************************************************************************/
bool
vs_upd_http_retrieval_get_request(vs_firmware_info_t **request) {

    //    if (uxQueueMessagesWaiting(*fwdist_event_queue)) {
    //        if (pdTRUE == xQueueReceive(*fwdist_event_queue, request, 0))
    //            return true;
    //    }
    *request = NULL;
    return false;
}
