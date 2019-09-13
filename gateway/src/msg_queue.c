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

#include <stdint.h>
#include <virgil/iot/macros/macros.h>
#include <FreeRTOS.h>
#include <queue.h>
#include <msg_queue.h>

static QueueHandle_t _queue = NULL;

#define QUEUE_SIZE  (64)

/******************************************************************************/
int
vs_msg_queue_init(void){

    _queue = xQueueCreate(QUEUE_SIZE, sizeof(vs_msg_queue_item_s));
    CHECK_RET(_queue, -1, "Unable to create messages queue");

    return 0;
}

/******************************************************************************/
void
vs_msg_queue_free(void){

    if(_queue){
        vQueueDelete(_queue);
    }
}

/******************************************************************************/
int
vs_msg_queue_push(vs_msg_queue_item_s *item, size_t wait_ticks){
    BaseType_t res;

    CHECK_NOT_ZERO_RET(item, -1);
    CHECK_NOT_ZERO_RET(_queue, -2);

    res = xQueueSend(_queue, item, wait_ticks);

    if( res == pdTRUE) {
        return 0;
    }

    return res;
}

/******************************************************************************/
int
vs_msg_queue_pop(vs_msg_queue_item_s *item, bool *has_read, size_t wait_ticks){
    BaseType_t res;

    CHECK_NOT_ZERO_RET(item, -1);
    CHECK_NOT_ZERO_RET(has_read, -2);
    CHECK_NOT_ZERO_RET(_queue, -3);

    *has_read = false;

    res = xQueueReceive(_queue, item, wait_ticks);

    if(res == pdTRUE){
        *has_read = true;
        return 0;
    } else if (res == pdFALSE && uxQueueMessagesWaiting(_queue) == 0) {
        return 0;
    }

    return -1;
}
