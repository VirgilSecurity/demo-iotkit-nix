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

#include <assert.h>
#include <pthread.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>
#include "helpers/msg-queue.h"

#define VS_NETIF_QUEUE_SZ (20)

static const vs_netif_t *_base_netif = 0;
static vs_netif_rx_cb_t _netif_rx_cb = 0;
static vs_netif_t _queued_netif = {0};
static vs_msg_queue_ctx_t *_queue_ctx = 0;
static pthread_t _queue_thread;
static bool _queue_thread_ready = false;

/******************************************************************************/
static int
_rx_to_queue(const struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    uint8_t *data_copy = NULL;

    assert(_queue_ctx);
    CHECK_RET(_queue_ctx, -1, "Queue context is Wrong");

    if (data) {
        data_copy = malloc(data_sz);
        if (data_sz) {
            memcpy(data_copy, data, data_sz);
            return vs_msg_queue_push(_queue_ctx, &_queued_netif, data_copy, data_sz);
        }
    }

    return -1;
}

/******************************************************************************/
static void *
_msg_processing(void *ctx) {
    const vs_netif_t *netif = 0;
    const uint8_t *data = 0;
    size_t data_sz = 0;

    assert(_queue_ctx);
    if (!_queue_ctx) {
        return NULL;
    }

    while (true) {
        // Block until new message appears.
        CHECK_RET(!vs_msg_queue_pop(_queue_ctx, (const void **)&netif, &data, &data_sz),
                  NULL,
                  "Error while reading message from queue");

        // Invoke callback function
        if (_netif_rx_cb) {
            _netif_rx_cb(netif, data, data_sz);
        }

        // Free data from Queue
        free((void *)data);
    }
    return NULL;
}


/******************************************************************************/
static int
_init_with_queue(const vs_netif_rx_cb_t netif_rx_cb) {
    assert(_base_netif);
    CHECK_RET(_base_netif, -1, "Unable to initialize queued Netif because of wrong Base Netif");

    // Initialize RX Queue
    _queue_ctx = vs_msg_queue_init(VS_NETIF_QUEUE_SZ, 1, 1);
    CHECK_RET(_queue_ctx, -1, "Cannot create message queue.");

    // Save Callback function
    _netif_rx_cb = netif_rx_cb;

    // Create thread to call Callbacks on data receive
    if (0 == pthread_create(&_queue_thread, NULL, _msg_processing, NULL)) {
        _queue_thread_ready = true;
        return _base_netif->init(_rx_to_queue);
    }

    VS_LOG_ERROR("Cannot start thread to process RX Queue");
    _queued_netif.deinit();

    return -1;
}

/******************************************************************************/
static int
_deinit_with_queue() {
    int res;

    // Stop base Network Interface
    res = _base_netif->deinit();

    // Stop RX processing thread
    if (_queue_thread_ready) {
        pthread_cancel(_queue_thread);
        pthread_join(_queue_thread, NULL);
        _queue_thread_ready = false;
    }

    // Free RX Queue
    if (_queued_netif.user_data) {
        vs_msg_queue_free(_queue_ctx);
    }

    // Clean user data
    _queued_netif.user_data = NULL;

    return res;
}

/******************************************************************************/
const vs_netif_t *
vs_netif_queued(const vs_netif_t *base_netif) {
    assert(base_netif);
    CHECK_RET(base_netif, NULL, "Unable to initialize queued Netif because of wrong Base Netif");
    _base_netif = base_netif;

    memcpy(&_queued_netif, base_netif, sizeof(_queued_netif));

    _queued_netif.init = _init_with_queue;
    _queued_netif.deinit = _deinit_with_queue;

    return &_queued_netif;
}

/******************************************************************************/
