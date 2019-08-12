/**
 * Copyright (C) 2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file alexa.c
 */
#include <stdbool.h>
#include <stdint.h>

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "event_groups.h"

#include "message_bin.h"
#include "gateway.h"
#include "gateway_macro.h"
#include "platform/platform_os.h"
#include "event_group_bit_flags.h"
#include <virgil/iot/cloud/cloud.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/update/update.h>
#include <cloud-config.h>

#define NUM_TOKENS 300

#define MB_QUEUE_SZ 10

xQueueHandle *upd_event_queue;

static xTaskHandle _mb_thread;
static const uint16_t _mb_thread_stack = 20 * 1024;

static vs_cloud_mb_mqtt_ctx_t _mb_mqtt_context;

static iot_message_handler_t _mb_mqtt_handler;

extern const uint8_t msg_bin_root_ca_crt[];

/*************************************************************************/
static void
_group_callback(AWS_IoT_Client *client,
                char *topic,
                uint16_t topic_sz,
                IoT_Publish_Message_Params *params,
                void *pData) {
    uint8_t *p = (uint8_t *)params->payload;
    p[params->payloadLen] = 0;
    VS_LOG_DEBUG("[MB] Message from topic %s", topic);
    VS_LOG_DEBUG("[MB] _group_callback params->payloadLen=%d", (int)params->payloadLen);
    if (params->payloadLen > UINT16_MAX) {
        VS_LOG_ERROR("[MB] Topic message is too big");
        return;
    }
    message_bin_process_command(topic, p, (uint16_t)params->payloadLen);
}

///*************************************************************************/
static int
_init_mqtt(const char *host, uint16_t port, const char *device_cert, const char *priv_key, const char *ca_cert) {

    return (SUCCESS == iot_init(&_mb_mqtt_handler, host, port, true, device_cert, priv_key, ca_cert))
                   ? VS_CLOUD_ERR_OK
                   : VS_CLOUD_ERR_FAIL;
}

/*************************************************************************/
static int
_connect_and_subscribe_to_topics(const char *client_id,
                                 const char *login,
                                 const char *password,
                                 const vs_cloud_mb_topics_list_t *topic_list) {
    return (SUCCESS == iot_connect_and_subscribe_multiple_topics(
                               &_mb_mqtt_handler, client_id, topic_list, login, password, QOS1, _group_callback, NULL))
                   ? VS_CLOUD_ERR_OK
                   : VS_CLOUD_ERR_FAIL;
}

/*************************************************************************/
static int
_mqtt_process() {
    return (SUCCESS == aws_iot_mqtt_yield(&_mb_mqtt_handler.client, 500)) ? VS_CLOUD_ERR_OK : VS_CLOUD_ERR_FAIL;
}

/*************************************************************************/
static void
_mb_mqtt_task(void *pvParameters) {
    VS_LOG_DEBUG("message bin thread started");
    vs_cloud_mb_init_ctx(&_mb_mqtt_context);

    while (true) {
        if (VS_CLOUD_ERR_OK == vs_cloud_mb_process(&_mb_mqtt_context,
                                                   (const char *)msg_bin_root_ca_crt,
                                                   _init_mqtt,
                                                   _connect_and_subscribe_to_topics,
                                                   _mqtt_process)) {
            vTaskDelay(100 / portTICK_PERIOD_MS);
        } else {
            vTaskDelay(5000 / portTICK_PERIOD_MS);
        }
    }
}

/*************************************************************************/
xTaskHandle *
start_message_bin_thread() {
    static bool is_threads_started = 0;
    if (!is_threads_started) {
        upd_event_queue = (xQueueHandle *)pvPortMalloc(sizeof(xQueueHandle));
        *upd_event_queue = xQueueCreate(MB_QUEUE_SZ, sizeof(upd_request_t *));
        is_threads_started =
                (pdTRUE == xTaskCreate(_mb_mqtt_task, "_mb_mqtt_task", _mb_thread_stack, 0, OS_PRIO_3, &_mb_thread));
    }
    return &_mb_thread;
}

/*************************************************************************/
static void
_firmware_topic_process(const uint8_t *p_data, const uint16_t length) {
    int res;
    upd_request_t *fw_url = (upd_request_t *)pvPortMalloc(sizeof(upd_request_t));
    fw_url->upd_type = MSG_BIN_UPD_TYPE_FW;

    res = vs_cloud_parse_firmware_manifest((char *)p_data, (int)length, fw_url->upd_file_url);
    // Like DNID

    if (VS_CLOUD_ERR_OK == res) {
        if (pdTRUE != xQueueSendToBack(*upd_event_queue, &fw_url, OS_NO_WAIT)) {
            VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
        } else {
            xEventGroupSetBits(get_gateway_ctx()->firmware_event_group, MSG_BIN_RECEIVE_BIT);
            return;
        }

    } else if (VS_CLOUD_ERR_NOT_FOUND == res) {
        VS_LOG_INFO("[MB] Firmware manifest contains old version\n");
    } else {
        VS_LOG_INFO("[MB] Error parse firmware manifest\n");
    }

    vPortFree(fw_url);
}

/*************************************************************************/
static void
_tl_topic_process(const uint8_t *p_data, const uint16_t length) {
    int res;
    upd_request_t *tl_url = (upd_request_t *)pvPortMalloc(sizeof(upd_request_t));
    tl_url->upd_type = MSG_BIN_UPD_TYPE_TL;

    res = vs_cloud_parse_tl_mainfest((char *)p_data, (int)length, tl_url->upd_file_url);

    if (VS_CLOUD_ERR_OK == res) {

        if (pdTRUE != xQueueSendToBack(*upd_event_queue, &tl_url, OS_NO_WAIT)) {
            VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
        } else {
            xEventGroupSetBits(get_gateway_ctx()->firmware_event_group, MSG_BIN_RECEIVE_BIT);
            return;
        }
    } else if (VS_CLOUD_ERR_NOT_FOUND == res) {
        VS_LOG_INFO("[MB] TL manifest contains old version\n");
    } else {
        VS_LOG_INFO("[MB] Error parse tl manifest\n");
    }

    vPortFree(tl_url);
}

#define VS_FW_TOPIC_MASK "fw/"
#define VS_TL_TOPIC_MASK "tl/"

/*************************************************************************/
void
message_bin_process_command(const char *topic, const uint8_t *p_data, const uint16_t length) {
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
bool
message_bin_get_request(upd_request_t **request) {

    if (uxQueueMessagesWaiting(*upd_event_queue)) {
        if (pdTRUE == xQueueReceive(*upd_event_queue, request, 0))
            return true;
    }
    *request = NULL;
    return false;
}
