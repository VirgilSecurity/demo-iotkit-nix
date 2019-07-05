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

#ifndef KUNLUN_HAL_NETIF_PLC_H
#define KUNLUN_HAL_NETIF_PLC_H

#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <arpa/inet.h>

typedef struct _iot_pkt {
    uint8_t *head;
    uint8_t *data;
    uint8_t *tail;
    uint8_t *end;
} iot_pkt_t;

typedef void (*iot_plc_recv_func_t)(void *param, iot_pkt_t *pkt);

typedef struct _iot_plc_app {
    /* application id */
    uint8_t app_id;
    /* default priority */
    uint8_t prio;
    /* callback to receive event from plc */
    iot_plc_recv_func_t recv;
    /* parameter that will be transferred back alone with the callback */
    void *param;
} iot_plc_app_t;

const vs_netif_t *
vs_hal_netif_plc();

void
vs_hal_netif_plc_force_mac(vs_mac_addr_t mac_addr);

void
vs_plc_sim_set_ip(struct in_addr address);

#endif // KUNLUN_HAL_NETIF_PLC_H
