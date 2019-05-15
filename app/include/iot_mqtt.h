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

#ifndef __AMAZON_MQTT__
#define __AMAZON_MQTT__

#include "aws_iot_mqtt_client_interface.h"

typedef struct {
    IoT_Client_Init_Params init_params;
    IoT_Client_Connect_Params connect_params;
    AWS_IoT_Client client;
} iot_message_handler_t;

#define UPD_URL_STR_SIZE 200

typedef struct {
    char *topic_list;
    uint16_t *topic_len_list;
    size_t topic_count;
} iot_topics_list_t;

/** The type of binary encoding */
typedef enum iot_tls_enc_type { IOT_TLS_ENC_PEM = 1, IOT_TLS_ENC_DER } tls_enc_type_t;

/** Representation of a TLS Certificate */
typedef struct iot_tls_cert {
    /** The type of the certificate */
    tls_enc_type_t cert_type;
    /** The buffer that holds the certificate */
    const unsigned char *cert;
    /** The size of the data in the buffer pointed to above */
    unsigned int cert_size;
} iot_tls_cert_t;

/** Representation of a TLS Key */
typedef struct iot_tls_key {
    /** The type of the key */
    tls_enc_type_t key_type;
    /** The buffer that holds the certificate */
    const unsigned char *key;
    /** The size of the data in the buffer pointed to above */
    unsigned int key_size;
} iot_tls_key_t;

IoT_Error_t
iot_init(iot_message_handler_t *handler,
         const char *host,
         uint16_t port,
         bool is_ssl_hostname_verify,
         const char *deviceCert,
         const char *priv_key,
         const char *rootCACert);

IoT_Error_t
iot_connect_and_subscribe_multiple_topics(
        iot_message_handler_t *handler,
        const char *client_id,
        const iot_topics_list_t *topic_list,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data);
IoT_Error_t
iot_connect_and_subscribe_topic(
        iot_message_handler_t *handler,
        const char *client_id,
        const char *topic,
        const char *login,
        const char *password,
        QoS qos,
        void (*iot_get_msg_handler)(AWS_IoT_Client *, char *, uint16_t, IoT_Publish_Message_Params *, void *),
        void *iot_get_msg_handler_data);

bool
iot_send(iot_message_handler_t *handler, const char *topic, uint8_t *data, size_t data_sz);

bool
iot_process(iot_message_handler_t *handler);

#endif //__AMAZON_MQTT__
