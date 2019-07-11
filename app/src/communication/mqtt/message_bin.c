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

#include "base64/base64.h"
#include "message_bin.h"
#include "gateway.h"
#include "gateway_macro.h"
#include "platform_os.h"
#include "tl_upgrade.h"
#include "fw_upgrade.h"
#include "event_group_bit_flags.h"
#include "json/json_parser.h"
#include "cloud.h"
#include "https.h"

#include <virgil/iot/logger/logger.h>

#define NUM_TOKENS 300

#define MB_QUEUE_SZ 10

xQueueHandle *upd_event_queue;

static xTaskHandle _mb_thread;
static const uint16_t _mb_thread_stack = 10 * 1024;

static _mb_mqtt_ctx_t _mb_mqtt_context;

static bool _mb_mqtt_init_done = false;

static iot_tls_cert_t mb_service_cert;
static iot_tls_key_t mb_service_key;
static iot_message_handler_t mb_mqtt_handler;

extern const uint8_t mb_root_ca_crt[];
const unsigned int MB_ROOT_CA_CRT_LEN = 58;

static const iot_tls_cert_t server_ca_cert = {
        .cert = (uint8_t *)mb_root_ca_crt,
        .cert_size = MB_ROOT_CA_CRT_LEN,
        .cert_type = IOT_TLS_ENC_PEM,
};

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
    VS_LOG_DEBUG("[MB] _group_callback params->payloadLen=%d, params->payload=%s", (int)params->payloadLen, p);
    if (params->payloadLen > UINT16_MAX) {
        VS_LOG_ERROR("[MB] Topic message is too big");
        return;
    }
    message_bin_process_command(topic, p, (uint16_t)params->payloadLen);
}

/*************************************************************************/
bool
mb_mqtt_provision_is_present() {
    return _mb_mqtt_context.is_filled;
}

/*************************************************************************/
void
mb_mqtt_ctx_free() {
    _mb_mqtt_context.is_filled = false;
    _mb_mqtt_init_done = false;

    if (_mb_mqtt_context.cert != NULL) {
        vPortFree(_mb_mqtt_context.cert);
        _mb_mqtt_context.cert = NULL;
    }

    if (_mb_mqtt_context.login != NULL) {
        vPortFree(_mb_mqtt_context.login);
        _mb_mqtt_context.login = NULL;
    }

    if (_mb_mqtt_context.password != NULL) {
        vPortFree(_mb_mqtt_context.password);
        _mb_mqtt_context.password = NULL;
    }

    if (_mb_mqtt_context.client_id != NULL) {
        vPortFree(_mb_mqtt_context.client_id);
        _mb_mqtt_context.client_id = NULL;
    }

    if (_mb_mqtt_context.pk != NULL) {
        vPortFree(_mb_mqtt_context.pk);
        _mb_mqtt_context.pk = NULL;
    }

    if (_mb_mqtt_context.topic_list.topic_list != NULL) {
        vPortFree(_mb_mqtt_context.topic_list.topic_list);
        _mb_mqtt_context.topic_list.topic_list = NULL;
    }

    if (_mb_mqtt_context.topic_list.topic_len_list != NULL) {
        vPortFree(_mb_mqtt_context.topic_list.topic_len_list);
        _mb_mqtt_context.topic_list.topic_len_list = NULL;
    }

    if (_mb_mqtt_context.port != 0)
        _mb_mqtt_context.port = 0;
}

/*************************************************************************/
static bool
mb_mqtt_is_active() {
    return _mb_mqtt_init_done;
}

/*************************************************************************/
static void
mb_mqtt_set_active() {
    _mb_mqtt_init_done = true;
}

/*************************************************************************/
void
mb_mqtt_task(void *pvParameters) {
    VS_LOG_DEBUG("message bin thread started");

    while (true) {
        if (!mb_mqtt_provision_is_present()) {
            msg_bin_get_credentials();
        }

        if (mb_mqtt_provision_is_present()) {
            if (!mb_mqtt_is_active()) {

                mb_service_cert.cert = (unsigned char *)_mb_mqtt_context.cert;
                mb_service_cert.cert_size = strlen(_mb_mqtt_context.cert) + 1;
                mb_service_cert.cert_type = IOT_TLS_ENC_PEM;
                mb_service_key.key_type = IOT_TLS_ENC_PEM;

                mb_service_key.key = (unsigned char *)_mb_mqtt_context.pk;
                mb_service_key.key_size = strlen(_mb_mqtt_context.pk) + 1;

                if (SUCCESS == iot_init(&mb_mqtt_handler,
                                        _mb_mqtt_context.host,
                                        _mb_mqtt_context.port,
                                        true,
                                        (char *)&mb_service_cert,
                                        (char *)&mb_service_key,
                                        (char *)&server_ca_cert) &&
                    SUCCESS == iot_connect_and_subscribe_multiple_topics(&mb_mqtt_handler,
                                                                         _mb_mqtt_context.client_id,
                                                                         &_mb_mqtt_context.topic_list,
                                                                         _mb_mqtt_context.login,
                                                                         _mb_mqtt_context.password,
                                                                         QOS1,
                                                                         _group_callback,
                                                                         NULL)) {
                    mb_mqtt_set_active();
                }
            } else {
                iot_process(&mb_mqtt_handler);
            }
        }
        if (!mb_mqtt_is_active()) {
            vTaskDelay(5000 / portTICK_RATE_MS);
        } else
            vTaskDelay(100 / portTICK_RATE_MS);
    }
}

/******************************************************************************/
bool
msg_bin_get_credentials() {

    if (mb_mqtt_provision_is_present()) {
        return false;
    }

    mb_mqtt_ctx_free();

    VS_LOG_DEBUG("------------------------- LOAD MESSAGE BIN CREDENTIALS -------------------------");

    size_t answer_size = HTTPS_INPUT_BUFFER_SIZE;
    char *answer = (char *)malloc(answer_size);
    if (!answer) {
        VS_LOG_ERROR("ALLOCATION FAIL in message bin credentials\r\n");
        // TODO: What should we do here ?
        while (1)
            ;
    }


    if (HTTPS_RET_CODE_OK == cloud_get_message_bin_credentials(answer, &answer_size)) {
        jobj_t jobj;

        _mb_mqtt_context.host = MESSAGE_BIN_BROKER_URL; /*host*/
        _mb_mqtt_context.port = MSG_BIN_MQTT_PORT;      /*port*/

        json_parse_start(&jobj, answer, answer_size);
        int len;
        /*----login----*/
        if (json_get_val_str_len(&jobj, "login", &len) != GATEWAY_OK || len < 0) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) answer not contain [login]!!!\r\n");
            goto clean;
        }
        ++len;
        _mb_mqtt_context.login = (char *)malloc((size_t)len);
        json_get_val_str(&jobj, "login", _mb_mqtt_context.login, len);
        /*----password----*/
        if (json_get_val_str_len(&jobj, "password", &len) != GATEWAY_OK || len < 0) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) answer not contain [password]");
            goto clean;
        }
        ++len;
        _mb_mqtt_context.password = (char *)malloc((size_t)len);
        json_get_val_str(&jobj, "password", _mb_mqtt_context.password, len);
        /*----client_id----*/
        if (json_get_val_str_len(&jobj, "client_id", &len) != GATEWAY_OK || len < 0) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) answer not contain [client_id]");
            goto clean;
        }
        ++len;
        _mb_mqtt_context.client_id = (char *)malloc((size_t)len);
        json_get_val_str(&jobj, "client_id", _mb_mqtt_context.client_id, len);
        /*----certificate----*/
        if (json_get_val_str_len(&jobj, "certificate", &len) != GATEWAY_OK || len < 0) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) answer not contain [certificate]");
            goto clean;
        }
        ++len;

        char *tmp = (char *)malloc((size_t)len);
        json_get_val_str(&jobj, "certificate", tmp, len);

        int decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            vPortFree(tmp);
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) wrong size [certificate]");
            goto clean;
        }

        _mb_mqtt_context.cert = (char *)malloc((size_t)decode_len);

        base64decode(tmp, len, (uint8_t *)_mb_mqtt_context.cert, &decode_len);
        vPortFree(tmp);

        /*----private_key----*/
        if (json_get_val_str_len(&jobj, "private_key", &len) != GATEWAY_OK || len < 0) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) answer not contain [private_key]");
            goto clean;
        }
        ++len;
        tmp = (char *)malloc((size_t)len);
        json_get_val_str(&jobj, "private_key", tmp, len);

        decode_len = base64decode_len(tmp, len);

        if (0 >= decode_len) {
            vPortFree(tmp);
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) wrong size [certificate]");
            goto clean;
        }

        _mb_mqtt_context.pk = (char *)malloc((size_t)decode_len);

        base64decode(tmp, len, (uint8_t *)_mb_mqtt_context.pk, &decode_len);
        vPortFree(tmp);

        /*----available_topics----*/
        int topic_count;
        if (json_get_array_object(&jobj, "available_topics", &topic_count) != GATEWAY_OK || topic_count < 0) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) answer not contain [available_topics]");
            goto clean;
        }
        _mb_mqtt_context.topic_list.topic_count = (size_t)topic_count;

        if (0 == _mb_mqtt_context.topic_list.topic_count) {
            VS_LOG_ERROR("Error!!! cloud_get_message_bin_credentials(...) [available_topics] is empty!");
            goto clean;
        } else {
            uint16_t i, total_topic_names_len = 0;
            len = 0;

            _mb_mqtt_context.topic_list.topic_len_list =
                    (uint16_t *)malloc(_mb_mqtt_context.topic_list.topic_count * sizeof(uint16_t));

            for (i = 0; i < _mb_mqtt_context.topic_list.topic_count; i++) {
                json_array_get_str_len(&jobj, i, &len);

                if (len + 1 > UINT16_MAX) {
                    VS_LOG_ERROR(
                            "Error!!! cloud_get_message_bin_credentials(...) [available_topics] name len is too big");
                    goto clean;
                }

                _mb_mqtt_context.topic_list.topic_len_list[i] = (uint16_t)(len + 1);
                total_topic_names_len += _mb_mqtt_context.topic_list.topic_len_list[i];
            }

            _mb_mqtt_context.topic_list.topic_list = (char *)malloc(total_topic_names_len);

            int offset = 0;

            for (i = 0; i < _mb_mqtt_context.topic_list.topic_count; i++) {
                json_array_get_str(
                        &jobj, i, _mb_mqtt_context.topic_list.topic_list + offset, total_topic_names_len - offset);

                json_array_get_str_len(&jobj, i, &len);
                offset += len;
                _mb_mqtt_context.topic_list.topic_list[offset] = '\0';
                offset++;
            }
        }

        _mb_mqtt_context.is_filled = true;
        vPortFree(answer);
        return true;
    }

clean:

    mb_mqtt_ctx_free();
    vPortFree(answer);
    return false;
}

/*************************************************************************/
xTaskHandle *
start_message_bin_thread() {
    static bool is_threads_started = 0;
    if (!is_threads_started) {
        upd_event_queue = (xQueueHandle *)pvPortMalloc(sizeof(xQueueHandle));
        *upd_event_queue = xQueueCreate(MB_QUEUE_SZ, sizeof(upd_request_t *));
        is_threads_started =
                (pdTRUE == xTaskCreate(mb_mqtt_task, "mb_mqtt_task", _mb_thread_stack, 0, OS_PRIO_3, &_mb_thread));
    }
    return &_mb_thread;
}

/*************************************************************************/
static void
_firmware_topic_process(const uint8_t *p_data, const uint16_t length) {

    upd_request_t *fw_url = (upd_request_t *)malloc(sizeof(upd_request_t));
    fw_url->upd_type = MSG_BIN_UPD_TYPE_FW;
    int status = parseFirmwareManifest((char *)p_data, (int)length, fw_url->upd_file_url, get_gateway_ctx());

    if (GATEWAY_OK == status) {
        if (pdTRUE != xQueueSendToBack(*upd_event_queue, &fw_url, OS_NO_WAIT)) {
            VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
            vPortFree(fw_url);
        } else {
            xEventGroupSetBits(get_gateway_ctx()->firmware_event_group, MSG_BIN_RECEIVE_BIT);
        }

    } else {
        VS_LOG_INFO("[MB] Error parse firmware manifest status = %d\n", status);
        vPortFree(fw_url);
    }
}

/*************************************************************************/
static void
_tl_topic_process(const uint8_t *p_data, const uint16_t length) {
    upd_request_t *tl_url = (upd_request_t *)malloc(sizeof(upd_request_t));
    tl_url->upd_type = MSG_BIN_UPD_TYPE_TL;
    int status = parse_tl_mainfest((char *)p_data, (int)length, tl_url->upd_file_url, get_gateway_ctx());

    if (GATEWAY_OK == status) {

        if (pdTRUE != xQueueSendToBack(*upd_event_queue, &tl_url, OS_NO_WAIT)) {
            VS_LOG_ERROR("[MB] Failed to send MSG BIN data to output processing!!!");
            vPortFree(tl_url);
        } else {
            xEventGroupSetBits(get_gateway_ctx()->firmware_event_group, MSG_BIN_RECEIVE_BIT);
        }

    } else {
        VS_LOG_INFO("[MB] Error parse tl manifest status = %d\n", status);
        vPortFree(tl_url);
    }
}

/*************************************************************************/
void
message_bin_process_command(const char *topic, const uint8_t *p_data, const uint16_t length) {
    char *ptr = strstr(topic, FW_TOPIC_MASK);
    if (ptr != NULL && topic == ptr) {
        _firmware_topic_process(p_data, length);
        return;
    }

    ptr = strstr(topic, TL_TOPIC_MASK);
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
