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

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/fldt_server.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include <sdmp_app.h>
#include <fldt_implementation.h>
#include <communication/rpi_netif.h>
#include <msg_queue.h>
#include <platform/platform_os.h>

#include <FreeRTOS.h>
#include <task.h>
#include <timers.h>

// The maximum amount of time the task should block waiting
// for space to become available on the queue,
// should it already be full

#define MSG_SEND_TIMEOUT_TICKS pdMS_TO_TICKS( 10 )

// The maximum amount of time the task should block waiting
// for an item to receive should the queue be empty
// at the time of the call

#define MSG_READ_TIMEOUT_TICKS pdMS_TO_TICKS( 100 )

// TODO : check msg task depth!
#define MSG_TASK_DEPTH  ( 3 * configMINIMAL_STACK_SIZE )
#define MSG_TASK_PRIORITY   ( OS_PRIO_3 )

static vs_netif_init_t _plc_init;
static vs_netif_deinit_t _plc_deinit;
static vs_netif_rx_cb_t _sdmp_rx;
static TaskHandle_t _msg_process_task = NULL;

/******************************************************************************/
static int
_rx_to_queue(const struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz){
    vs_msg_queue_item_s item;

    item.netif = netif;
    item.data = malloc(data_sz);
    item.size = data_sz;

    if(item.data) {
        memcpy(item.data, data, data_sz);
        return vs_msg_queue_push(&item, MSG_SEND_TIMEOUT_TICKS);
    }

    return -1;
}

/******************************************************************************/
static int
_init_with_queue(const vs_netif_rx_cb_t rx_cb, const struct vs_netif_t *netif){
    vs_msg_queue_init();

    _sdmp_rx = rx_cb;

    return _plc_init(_rx_to_queue, netif);
}

/******************************************************************************/
static int
_deinit_with_queue(){
    int res;

    res = _plc_deinit();

    vs_msg_queue_free();

    return res;
}

/******************************************************************************/
static const vs_netif_t *
_init_msg_queued_netif(void){
    static vs_netif_t netif;

    memcpy(&netif, vs_hal_netif_plc(), sizeof(netif));

    _plc_init = netif.init;
    _plc_deinit = netif.deinit;

    netif.init = _init_with_queue;
    netif.deinit = _deinit_with_queue;

    return &netif;
}

/******************************************************************************/
static void
_msg_processing(void *data){
    vs_msg_queue_item_s item;
    bool has_read;
    int res;

    while(true){
        CHECK(!vs_msg_queue_pop(&item, &has_read, MSG_READ_TIMEOUT_TICKS), "Error while reading message from queue");

        if(has_read){
            res = _sdmp_rx(item.netif, item.data, item.size);
            free(item.data);
            CHECK(!res, "Error while processing message");
        }

        terminate:  ;
    }
}

/******************************************************************************/
static int
_create_msg_processing_thread(void){

    CHECK_RET(pdPASS == xTaskCreate(_msg_processing, "MsgProc", MSG_TASK_DEPTH, NULL, MSG_TASK_PRIORITY, &_msg_process_task),
              -1,
              "Unable to create messages processing task");

    return 0;
}

/******************************************************************************/
int
vs_sdmp_comm_start_thread(const vs_mac_addr_t *mac) {

    const vs_netif_t *plc_netif = _init_msg_queued_netif();

    CHECK_RET(!_create_msg_processing_thread(), -1, "Unable to create SDMP messages processing task");

    CHECK_RET(!vs_sdmp_init(plc_netif), -2, "Unable to initialize SDMP over PLC interface");

    CHECK_RET(!vs_sdmp_register_service(vs_sdmp_fldt_service(plc_netif)), -3, "Unable to register FLDT service");

    return 0;
}

/******************************************************************************/
