/**
 * Copyright (C) 2017 Virgil Security Inc.
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
 * @file cloud.h
 * @brief cloud service API.
 */

#ifndef GATEWAY_CLOUD_H_
#define GATEWAY_CLOUD_H_
#include <stdint.h>
#include <stdbool.h>

#define CLOUD_OK 0
#define CLOUD_FAIL -1
#define CLOUD_HTTP_BUFFER_TO_SMALL -2
#define CLOUD_CALCULATE_SIGNATURE_FAIL -3
#define CLOUD_CONFIG_JSON_FAIL -4
#define CLOUD_ANSWER_JSON_FAIL -5
#define CLOUD_DECRYPT_ANSWER_JSON_FAIL -6
#define CLOUD_VALUE_ANSWER_JSON_FAIL -7
#define CLOUD_GENERATE_AUTHORIZATION_FAIL -8

#define MESSAGE_BIN_BROKER_URL ""
#define CLOUD_HOST ""
#define THING_EP "thing"
#define AWS_ID "/%s/aws"
#define MQTT_ID "/%s/mqtt"

int16_t
cloud_get_gateway_iot(char *out_answer, uint16_t *in_out_answer_len);
int16_t
cloud_get_message_bin_credentials(char *out_answer, uint16_t *in_out_answer_len);

#endif /* GATEWAY_CLOUD_H_ */
