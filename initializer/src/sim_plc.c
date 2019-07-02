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

#include "iot_plc_api.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

static iot_plc_app_t _iot_plc_app;
static int _plc_sock = -1;
static pthread_t receive_thread;
static uint8_t _sim_mac_addr[6] = {2, 2, 2, 2, 2, 2};

static bool _plc_sim_ip_ready = false;
static struct in_addr _plc_sim_ip;

#define PLC_SIM_PORT 3333

#define PLC_RX_BUF_SZ (2048)
#define PLC_RESERVED_SZ (128)

/******************************************************************************/
static void *
_plc_receive_processor(void *sock_desc) {
    uint8_t received_data[PLC_RX_BUF_SZ];
    iot_pkt_t pkt;
    ssize_t recv_sz;
    uint8_t *data_buf;

    // Fill packet info
    pkt.head = received_data;
    pkt.data = &received_data[PLC_RESERVED_SZ];
    pkt.end = &received_data[PLC_RX_BUF_SZ - 1];

    data_buf = pkt.data;

    while (1) {
        memset(received_data, 0, PLC_RX_BUF_SZ);
        recv_sz = recv(_plc_sock, data_buf, PLC_RX_BUF_SZ - PLC_RESERVED_SZ, 0);
        if (recv_sz > 0) {
            // Process received packet
            pkt.tail = &data_buf[recv_sz];

            // Pass received data to upper level via callback
            if (_iot_plc_app.recv) {
                _iot_plc_app.recv(_iot_plc_app.param, &pkt);
            }
        } else if (0 == recv_sz || (-1 == recv_sz && errno != EAGAIN && errno != ETIMEDOUT)) {
            printf("TCP socket disconnect res = %d (%s)\n", (int)recv_sz, strerror(errno));
            break;
        }
    }

    return NULL;
}

/******************************************************************************/
static int
_plc_connect() {
    struct sockaddr_in server;

    // Check is present IP of PLC bus simulator
    if (!_plc_sim_ip_ready) {
        printf("ERROR: IP of PLC bus simulator is not present\n");
        return -1;
    }

    // Create socket
    _plc_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_plc_sock == -1) {
        printf("Could not create socket\n");
    }

    server.sin_addr = _plc_sim_ip;
    server.sin_family = AF_INET;
    server.sin_port = htons(PLC_SIM_PORT);

    // Connect to remote server
    if (connect(_plc_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connect failed. Error\n");
        return 1;
    }

    printf("Connected to PLC bus\n");

    pthread_create(&receive_thread, NULL, _plc_receive_processor, NULL);

    return 0;
}

/******************************************************************************/
iot_plc_app_h
iot_plc_register_app(iot_plc_app_t *app) {

    // Save PLC App info
    memcpy(&_iot_plc_app, app, sizeof(_iot_plc_app));

    // Connect to PLC simulator
    _plc_connect();

    return &_iot_plc_app;
}

/******************************************************************************/
void
iot_plc_send_msdu(iot_plc_app_h handle, iot_pkt_t *pkt) {
    if (_plc_sock <= 0) {
        return;
    }

    send(_plc_sock, pkt->data, pkt->tail - pkt->data, 0);
}

/******************************************************************************/
iot_pkt_t *
iot_plc_alloc_msdu(iot_plc_app_h handle,
                   uint8_t msg_type,
                   uint8_t ack_type,
                   uint8_t *dst,
                   uint8_t *src,
                   uint8_t lid,
                   uint16_t len,
                   uint8_t retry_cnt) {
    iot_pkt_t *pkt;

    pkt = calloc(1, sizeof(iot_pkt_t));

    pkt->head = calloc(1, 2048);
    pkt->data = pkt->tail = pkt->head;
    pkt->end = pkt->head + 2048;

    return pkt;
}

/******************************************************************************/
void
iot_pkt_free(iot_pkt_t *buf) {
    free(buf->head);
    free(buf);
}

/******************************************************************************/
void
iot_plc_set_cfg(iot_plc_app_h handle, uint8_t *addr, uint8_t dev_type, uint8_t reset) {
    memcpy(_sim_mac_addr, addr, 6);
}

/******************************************************************************/
void
iot_plc_get_cfg(iot_plc_app_h handle, uint8_t addr[6], uint8_t dev_type) {
    memcpy(addr, _sim_mac_addr, 6);
}

/******************************************************************************/

uint32_t
iot_oem_get_module_mac(uint8_t *mac) {
    memcpy(mac, _sim_mac_addr, 6);
    return 0;
}

/******************************************************************************/
void
vs_plc_sim_set_ip(struct in_addr address) {
    memcpy(&_plc_sim_ip, &address, sizeof(_plc_sim_ip));
    _plc_sim_ip_ready = true;
}