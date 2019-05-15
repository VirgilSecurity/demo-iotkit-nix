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

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>

#include "communication/gateway_netif_plc.h"

static int
_plc_init(const vs_netif_rx_cb_t rx_cb);
static int
_plc_deinit();
static int
_plc_tx(const uint8_t *data, const uint16_t data_sz);
static int
_plc_mac(struct vs_mac_addr_t *mac_addr);

static const vs_netif_t _netif_plc = {
        .user_data = NULL,
        .init = _plc_init,
        .deinit = _plc_deinit,
        .tx = _plc_tx,
        .mac_addr = _plc_mac,
};

static vs_netif_rx_cb_t _netif_plc_rx_cb = 0;

static iot_plc_app_t _iot_plc_app;
static int _plc_sock = -1;
static pthread_t receive_thread;
static uint8_t _sim_mac_addr[6] = {2, 2, 2, 2, 2, 2};

#define PLC_SIM_ADDR "127.0.0.1"
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
        if (recv_sz < 0) {
            printf("PLC recv failed\n");
        }

        if (!recv_sz) {
            continue;
        }

        pkt.tail = &data_buf[recv_sz];

        // Pass received data to upper level via callback
        if (_iot_plc_app.recv) {
            _iot_plc_app.recv(_iot_plc_app.param, &pkt);
        }
    }

    return NULL;
}

/******************************************************************************/
static int
_plc_connect() {
    struct sockaddr_in server;

    // Create socket
    _plc_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (_plc_sock == -1) {
        printf("Could not create socket\n");
    }

    server.sin_addr.s_addr = inet_addr(PLC_SIM_ADDR);
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
static void
_gateway_plc_recv(void *param, iot_pkt_t *pkt) {
    vs_netif_t *netif;
    netif = (vs_netif_t *)param;

    assert(netif);
    assert(pkt);
    assert(_netif_plc_rx_cb);

    /*
     *---------- <-- head_ptr (fixed)
     *|  head  |
     *|--------| <-- data_ptr
     *|  data  |
     *|        |
     *|--------| <-- tail_ptr
     *|  tail  |
     *---------- <-- end_ptr (fixed)
     */

    _netif_plc_rx_cb(netif, pkt->data, pkt->tail - pkt->data);
}

/******************************************************************************/
static int
_plc_tx(const uint8_t *data, const uint16_t data_sz) {
    iot_pkt_t pkt;

    pkt.head = pkt.data = (uint8_t *)data;
    pkt.tail = pkt.end = pkt.head + data_sz;

    if (_plc_sock <= 0) {
        return 0;
    }

    send(_plc_sock, pkt.data, pkt.tail - pkt.data, 0);

    return 0;
}

/******************************************************************************/
static int
_plc_init(const vs_netif_rx_cb_t rx_cb) {
    assert(rx_cb);
    _netif_plc_rx_cb = rx_cb;

    memset(&_iot_plc_app, 0, sizeof(_iot_plc_app));

    _iot_plc_app.param = (void *)&_netif_plc;
    _iot_plc_app.recv = _gateway_plc_recv;

    _plc_connect();

    return 0;
}

/******************************************************************************/
static int
_plc_deinit() {
    return 0;
}

/******************************************************************************/
static int
_plc_mac(struct vs_mac_addr_t *mac_addr) {

    if (mac_addr) {
        memcpy(mac_addr->bytes, _sim_mac_addr, 6);
        return 0;
    }

    return -1;
}

/******************************************************************************/
const vs_netif_t *
vs_hal_netif_plc() {
    return &_netif_plc;
}

/******************************************************************************/
void
vs_hal_netif_plc_force_mac(vs_mac_addr_t mac_addr) {
    memcpy(_sim_mac_addr, mac_addr.bytes, 6);
}

/******************************************************************************/