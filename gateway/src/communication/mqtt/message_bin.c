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

#include <stdbool.h>
#include <stdint.h>

#include "message_bin.h"
#include "gateway.h"
#include "event-flags.h"
#include <virgil/iot/cloud/cloud.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/firmware/firmware.h>
#include <cloud-config.h>
#include "helpers/msg-queue.h"

#define MB_QUEUE_SZ 10

static vs_msg_queue_ctx_t *upd_event_queue = NULL;
static pthread_t _mb_thread;

extern const uint8_t msg_bin_root_ca_crt[];

#define VS_FW_TOPIC_MASK "fw/"
#define VS_TL_TOPIC_MASK "tl/"

/*************************************************************************/
static void
_firmware_topic_process(const uint8_t *p_data, const uint16_t length) {
    int res;
    gtwy_t *gtwy = get_gateway_ctx();
    upd_request_t *fw_url = (upd_request_t *)malloc(sizeof(upd_request_t));
    assert(NULL != fw_url);
    if (NULL == fw_url) {
        VS_LOG_ERROR("Can't allocate memory");
        exit(-1);
    }

    fw_url->upd_type = MSG_BIN_UPD_TYPE_FW;

    if (0 == pthread_mutex_lock(&gtwy->firmware_mutex)) {
        res = vs_cloud_parse_firmware_manifest(&gtwy->fw_update_ctx, (char *)p_data, (int)length, fw_url->upd_file_url);
        pthread_mutex_unlock(&gtwy->firmware_mutex);

        if (VS_CODE_OK == res) {

            if (0 != vs_msg_queue_push(upd_event_queue, fw_url, NULL, 0)) {
                VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
            } else {
                vs_event_group_set_bits(&gtwy->message_bin_events, MSG_BIN_RECEIVE_BIT);
                return;
            }

        } else if (VS_CODE_ERR_NOT_FOUND == res) {
            VS_LOG_INFO("[MB] Firmware manifest contains old version\n");
        } else {
            VS_LOG_INFO("[MB] Error parse firmware manifest\n");
        }
    }

    free(fw_url);
}

/*************************************************************************/
static void
_tl_topic_process(const uint8_t *p_data, const uint16_t length) {
    int res;
    gtwy_t *gtwy = get_gateway_ctx();
    upd_request_t *tl_url = (upd_request_t *)malloc(sizeof(upd_request_t));
    assert(NULL != tl_url);
    if (NULL == tl_url) {
        VS_LOG_ERROR("Can't allocate memory");
        exit(-1);
    }

    tl_url->upd_type = MSG_BIN_UPD_TYPE_TL;

    res = vs_cloud_parse_tl_mainfest((char *)p_data, (int)length, tl_url->upd_file_url);

    if (VS_CODE_OK == res) {

        if (0 != vs_msg_queue_push(upd_event_queue, tl_url, NULL, 0)) {
            VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
        } else {
            vs_event_group_set_bits(&gtwy->message_bin_events, MSG_BIN_RECEIVE_BIT);
            return;
        }
    } else if (VS_CODE_ERR_NOT_FOUND == res) {
        VS_LOG_INFO("[MB] TL manifest contains old version\n");
    } else {
        VS_LOG_INFO("[MB] Error parse tl manifest\n");
    }

    free(tl_url);
}

/*************************************************************************/
static void
_process_topic(const char *topic, uint16_t topic_sz, const uint8_t *p_data, uint16_t length) {
    char *ptr = strstr(topic, VS_FW_TOPIC_MASK);
    if (ptr != NULL && topic == ptr) {
        _firmware_topic_process(p_data, length);
        return;
    }

    ptr = strstr(topic, VS_TL_TOPIC_MASK);
    if (ptr != NULL && topic == ptr) {
        _tl_topic_process(p_data, length);
        return;
    }
}

/*************************************************************************/
static void *
_mb_mqtt_task(void *pvParameters) {
    VS_LOG_DEBUG("message bin thread started");

    while (true) {
        if (VS_CODE_OK == vs_cloud_message_bin_process(_process_topic, (const char *)msg_bin_root_ca_crt)) {
            vs_impl_msleep(500);
        } else {
            vs_impl_msleep(5000);
        }
    }
    return NULL;
}

/*************************************************************************/
pthread_t *
start_message_bin_thread() {
    static bool is_threads_started = 0;
    if (!is_threads_started) {

        upd_event_queue = vs_msg_queue_init(MB_QUEUE_SZ, 1, 1);

        is_threads_started = (0 == pthread_create(&_mb_thread, NULL, _mb_mqtt_task, NULL));
        if (!is_threads_started) {
            return NULL;
        }
    }
    return &_mb_thread;
}

/*************************************************************************/
bool
message_bin_get_request(upd_request_t **request) {
    const uint8_t *data;
    size_t _sz;
    *request = NULL;
    if (vs_msg_queue_data_present(upd_event_queue)) {
        if (0 == vs_msg_queue_pop(upd_event_queue, (void *)request, &data, &_sz)) {
            return true;
        }
    }

    return false;
}
