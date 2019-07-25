/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include "aws_iot_log.h"
#include "aws_iot_error.h"
#include <string.h>
#include <stdio.h>
#include "iot_mqtt.h"
#include <virgil/iot/logger/logger.h>

/******************************************************************************/
static void
disconnect_callback(AWS_IoT_Client *client, void *data) {
    VS_LOG_WARNING("MQTT Disconnect");
    IoT_Error_t rc = FAILURE;
    if (client)
        return;

    IOT_UNUSED(data);

    if (aws_iot_is_autoreconnect_enabled(client)) {
        VS_LOG_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
    } else {
        VS_LOG_WARNING("Auto Reconnect not enabled. Starting manual reconnect...");
        rc = aws_iot_mqtt_attempt_reconnect(client);
        if (NETWORK_RECONNECTED == rc) {
            VS_LOG_WARNING("Manual Reconnect Successful");
        } else {
            VS_LOG_WARNING("Manual Reconnect Failed - %d", rc);
        }
    }
}

/******************************************************************************/
IoT_Error_t
iot_init(iot_message_handler_t *handler,
         const char *host,
         uint16_t port,
         bool is_ssl_hostname_verify,
         const char *deviceCert,
         const char *priv_key,
         const char *rootCACert) {

    IoT_Error_t rc = SUCCESS;
    handler->init_params = iotClientInitParamsDefault;
    handler->connect_params = iotClientConnectParamsDefault;

    IoT_Client_Init_Params *mqttInitParams = &handler->init_params;

    memset(mqttInitParams, 0, sizeof(IoT_Client_Init_Params));

    mqttInitParams->enableAutoReconnect = false; // We enable this later below
    mqttInitParams->pHostURL = (char *)host;
    mqttInitParams->port = port;
    mqttInitParams->pDeviceCertLocation = (char *)deviceCert;
    mqttInitParams->pDevicePrivateKeyLocation = (char *)priv_key;
    mqttInitParams->pRootCALocation = (char *)rootCACert;
    mqttInitParams->mqttCommandTimeout_ms = 20000;
    mqttInitParams->tlsHandshakeTimeout_ms = 15000;
    mqttInitParams->isSSLHostnameVerify = is_ssl_hostname_verify;
    mqttInitParams->disconnectHandler = disconnect_callback;
    mqttInitParams->disconnectHandlerData = NULL;
    rc = aws_iot_mqtt_init(&handler->client, mqttInitParams);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("iot_mqtt_init returned error : %d ", rc);
    }

    return rc;
}

/******************************************************************************/
static char *
get_topic_name_by_index(const vs_cloud_mb_topics_list_t *topic_list, uint32_t index) {
    uint32_t i;
    char *topic_list_ptr = topic_list->topic_list;

    if (index >= topic_list->topic_count)
        return NULL;

    for (i = 0; i < index; ++i) {
        topic_list_ptr += topic_list->topic_len_list[i];
    }
    return topic_list_ptr;
}

/******************************************************************************/
static IoT_Error_t
iot_connect_internal(
        iot_message_handler_t *handler,
        const char *client_id,
        const char *login,
        const char *password,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *)) {
    IoT_Error_t rc;
    IoT_Client_Connect_Params *pConnectParams = &handler->connect_params;
    pConnectParams->keepAliveIntervalInSec = 10;
    pConnectParams->isCleanSession = true;
    pConnectParams->MQTTVersion = MQTT_3_1_1;
    pConnectParams->pClientID = (char *)client_id;
    pConnectParams->clientIDLen = (uint16_t)strlen(client_id);
    pConnectParams->isWillMsgPresent = false;
    pConnectParams->pUsername = (char *)login;
    pConnectParams->pPassword = (char *)password;
    if (login) {
        pConnectParams->usernameLen = (uint16_t)strlen(login);
    } else {
        pConnectParams->usernameLen = 0;
    }
    if (password) {
        pConnectParams->passwordLen = (uint16_t)strlen(password);
    } else {
        pConnectParams->passwordLen = 0;
    }

    VS_LOG_INFO("Connecting...");
    rc = aws_iot_mqtt_connect(&handler->client, pConnectParams);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("Error(%d) connecting to %s:%d", rc, handler->init_params.pHostURL, handler->init_params.port);
        return rc;
    }

    /*
     * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
     *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
     *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
     */
    rc = aws_iot_mqtt_autoreconnect_set_status(&handler->client, true);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("Unable to set Auto Reconnect to true - %d", rc);
    }
    return rc;
}

/******************************************************************************/
IoT_Error_t
iot_connect_and_subscribe_multiple_topics(
        iot_message_handler_t *handler,
        const char *client_id,
        const vs_cloud_mb_topics_list_t *topic_list,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data) {


    IoT_Error_t rc;
    uint32_t i;
    rc = iot_connect_internal(handler, client_id, login, password, iot_get_msg_handler);
    if (SUCCESS != rc) {
        return rc;
    }

    rc = FAILURE;
    for (i = 0; i < topic_list->topic_count; ++i) {
        char *topic_name = get_topic_name_by_index(topic_list, i);

        if (0 == topic_list->topic_len_list[i]) {
            continue;
        }

        VS_LOG_INFO("Subscribing to topic %s", topic_name);
        rc = aws_iot_mqtt_subscribe(&handler->client,
                                    topic_name,
                                    topic_list->topic_len_list[i] - (uint16_t)1,
                                    qos,
                                    iot_get_msg_handler,
                                    iot_get_msg_handler_data);
        if (SUCCESS != rc) {
            VS_LOG_ERROR("Error subscribing %s : %d ", topic_name, rc);
        } else {
            VS_LOG_INFO("Success subscribing %s", topic_name);
            rc = SUCCESS;
        }
    }

    return rc;
}

/******************************************************************************/
IoT_Error_t
iot_connect_and_subscribe_topic(
        iot_message_handler_t *handler,
        const char *client_id,
        const char *topic,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data) {

    IoT_Error_t rc;
    rc = iot_connect_internal(handler, client_id, login, password, iot_get_msg_handler);
    if (SUCCESS != rc) {
        return rc;
    }

    VS_LOG_INFO("Subscribing to topic %s", topic);
    rc = aws_iot_mqtt_subscribe(
            &handler->client, topic, (uint16_t)strlen(topic), qos, iot_get_msg_handler, iot_get_msg_handler_data);
    if (SUCCESS != rc) {
        VS_LOG_ERROR("Error subscribing %s: %d ", topic, rc);
    }

    return rc;
}

/******************************************************************************/
bool
iot_send(iot_message_handler_t *handler, const char *topic, uint8_t *data, size_t data_sz) {
    IoT_Publish_Message_Params param;
    param.qos = QOS0;
    param.payload = data;
    param.payloadLen = data_sz;
    param.isRetained = 0;
    IoT_Error_t rc;
    // Max time the yield function will wait for read messages
    iot_process(handler);

    if (SUCCESS != (rc = aws_iot_mqtt_publish(&handler->client, topic, (uint16_t)strlen(topic), &param))) {
        VS_LOG_ERROR("Error send to topic %s: %d ", topic, rc);
        return false;
    }
    iot_process(handler);
    return true;
}

/******************************************************************************/
bool
iot_process(iot_message_handler_t *handler) {
    return SUCCESS == aws_iot_mqtt_yield(&handler->client, 500);
}
