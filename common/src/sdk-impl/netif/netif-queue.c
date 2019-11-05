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
#include <unistd.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/protocols/sdmp/sdmp-structs.h>
#include "helpers/msg-queue.h"

#define VS_NETIF_QUEUE_SZ (100)

static const vs_netif_t *_base_netif = 0;
static vs_netif_process_cb_t _netif_process_cb = 0;
static vs_netif_t _queued_netif = {0};
static vs_msg_queue_ctx_t *_queue_ctx = 0;
static pthread_t _queue_thread;
static bool _queue_thread_ready = false;
static pthread_t _periodical_thread;
static bool _periodical_ready = false;
static volatile bool _stop_queue = false;
static volatile bool _stop_periodical = false;

/******************************************************************************/
static vs_status_e
_queue_and_process(struct vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    assert(_queue_ctx);
    CHECK_RET(_queue_ctx, -1, "Queue context is Wrong");

    if (data && data_sz) {
        return vs_msg_queue_push(_queue_ctx, &_queued_netif, data, data_sz);
    }

    return VS_CODE_ERR_NULLPTR_ARGUMENT;
}

/******************************************************************************/
static void *
_msg_processing(void *ctx) {
    vs_netif_t *netif = 0;
    const uint8_t *data = 0;
    size_t data_sz = 0;

    assert(_queue_ctx);
    if (!_queue_ctx) {
        return NULL;
    }

    while (!_stop_queue) {
        // Block until new message appears.
        CHECK_RET(VS_CODE_OK == vs_msg_queue_pop(_queue_ctx, (const void **)&netif, &data, &data_sz),
                  NULL,
                  "Error while reading message from queue");

        // Invoke callback function
        if (_netif_process_cb) {
            _netif_process_cb(netif, data, data_sz);
        }

        // Free data from Queue
        free((void *)data);
    }
    return NULL;
}

/******************************************************************************/
static void *
_periodical_processing(void *ctx) {
    while (!_stop_periodical) {
        sleep(1);
        CHECK_RET(VS_CODE_OK == vs_msg_queue_push(_queue_ctx, NULL, NULL, 0),
                  NULL,
                  "Error while writing message to queue");
    }
    return NULL;
}

/******************************************************************************/
static vs_status_e
_init_with_queue(const vs_netif_rx_cb_t netif_rx_cb, const vs_netif_process_cb_t netif_process_cb) {
    assert(_base_netif);
    CHECK_RET(_base_netif, -1, "Unable to initialize queued Netif because of wrong Base Netif");

    // Initialize RX Queue
    _queue_ctx = vs_msg_queue_init(VS_NETIF_QUEUE_SZ, 1, 1);
    CHECK_RET(_queue_ctx, -1, "Cannot create message queue.");

    // Save Callback function
    _netif_process_cb = netif_process_cb;

    // Create thread for periodical actions
    if (0 == pthread_create(&_periodical_thread, NULL, _periodical_processing, NULL)) {
        _periodical_ready = true;
    }

    // Create thread to call Callbacks on data receive
    if (0 == pthread_create(&_queue_thread, NULL, _msg_processing, NULL)) {
        _queue_thread_ready = true;
        return _base_netif->init(netif_rx_cb, _queue_and_process);
    }

    VS_LOG_ERROR("Cannot start thread to process RX Queue");
    _queued_netif.deinit();

    return VS_CODE_ERR_THREAD;
}

/******************************************************************************/
static vs_status_e
_deinit_with_queue() {
    vs_status_e res;

    // Stop base Network Interface
    res = _base_netif->deinit();

    // Stop RX processing thread
    if (_queue_thread_ready) {
        _stop_queue = true;
        pthread_join(_queue_thread, NULL);
        _queue_thread_ready = false;
    }

    // Free RX Queue
    if (_queued_netif.user_data) {
        vs_msg_queue_free(_queue_ctx);
    }

    // Clean user data
    _queued_netif.user_data = NULL;

    // Stop periodical thread
    if (_periodical_ready) {
        _stop_periodical = true;
        pthread_join(_periodical_thread, NULL);
        _periodical_ready = false;
    }

    return res;
}

/******************************************************************************/
vs_netif_t *
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
