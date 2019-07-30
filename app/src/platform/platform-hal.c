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

#include "FreeRTOS.h"
#include <string.h>
#include <global-hal.h>
#include <gateway.h>
#include <virgil/iot/cloud/cloud.h>
#include <virgil/iot/provision/provision.h>

#define GW_MANUFACTURE_ID                                                                                              \
    { 'V', 'R', 'G', 'L' }
#define GW_DEVICE_TYPE                                                                                                 \
    { 'G', 'T', 'W', 'Y' }
#define GW_APP_TYPE                                                                                                    \
    { 'A', 'P', 'P', '0' }

// TODO: Need to use real descriptor, which
static const vs_firmware_descriptor_t _descriptor = {
        .manufacture_id = GW_MANUFACTURE_ID,
        .device_type = GW_DEVICE_TYPE,
        .version.app_type = GW_APP_TYPE,
        .version.major = 0,
        .version.minor = 1,
        .version.patch = 3,
        .version.dev_milestone = 'm',
        .version.dev_build = 0,
        .version.timestamp = 0,
        .padding = 0,
        .chunk_size = 256,
        .firmware_length = 2097152,
        .app_size = 2097152,
};

/******************************************************************************/
void *
platform_malloc(size_t size) {
    return pvPortMalloc(size);
}

/******************************************************************************/
void
platform_free(void *ptr) {
    return vPortFree(ptr);
}

/******************************************************************************/
void *
platform_calloc(size_t num, size_t size) {

    void *ptr;

    vTaskSuspendAll();
    { ptr = calloc(num, size); }
    xTaskResumeAll();

    return ptr;
}

/******************************************************************************/
void
vs_global_hal_get_udid_of_device(uint8_t udid[SERIAL_SIZE]) {
    memcpy(udid, get_gateway_ctx()->udid_of_device, SERIAL_SIZE);
}

/******************************************************************************/
const vs_firmware_descriptor_t *
vs_global_hal_get_firmware_descriptor(void) {
    return &_descriptor;
}

/******************************************************************************/
int
vs_cloud_store_firmware_hal(vs_firmware_descriptor_t *descriptor, uint8_t *data, uint32_t data_size, uint32_t offset) {
    // TODO: Need to implement
    return VS_CLOUD_ERR_OK;
}