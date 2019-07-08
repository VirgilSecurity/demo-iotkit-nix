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
#include <stdbool.h>
#include <stdio.h>
#include <virgil/iot/secbox/secbox.h>

#include "gateway_macro.h"
#include "secbox_impl/file_io_hal.h"

static int
vs_secbox_gateway_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, uint16_t data_sz);

static int
vs_secbox_gateway_save(vs_secbox_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz);

static int
vs_secbox_gateway_del(vs_secbox_element_info_t *element_info);

static int
vs_secbox_gateway_init();

static vs_secbox_hal_impl_t _secbox_gateway = {.save = vs_secbox_gateway_save,
                                               .load = vs_secbox_gateway_load,
                                               .del = vs_secbox_gateway_del,
                                               .init = vs_secbox_gateway_init};

/******************************************************************************/
static int
vs_secbox_gateway_save(vs_secbox_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz) {
    // TODO: need to remove asserts
    assert(element_info);
    assert(in_data);

    char filename[FILENAME_MAX];

    snprintf(filename, sizeof(filename), "%u_%u_%u", element_info->storage_type, element_info->id, element_info->index);

    return write_trustlist_file(filename, in_data, data_sz);
}

/******************************************************************************/
static int
vs_secbox_gateway_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, uint16_t data_sz) {
    assert(element_info);
    assert(out_data);

    uint16_t out_sz;
    char filename[FILENAME_MAX];

    snprintf(filename, sizeof(filename), "%u_%u_%u", element_info->storage_type, element_info->id, element_info->index);

    // TODO: RETURN REAL SIZE OF READ DATA
    return read_trustlist_file(filename, out_data, data_sz, &out_sz);
}

/******************************************************************************/
static int
vs_secbox_gateway_del(vs_secbox_element_info_t *element_info) {
    assert(element_info);

    // TODO: Need to implement
    return -1;
}


/******************************************************************************/
static int
vs_secbox_gateway_init() {
    return GATEWAY_OK;
}

/******************************************************************************/
const vs_secbox_hal_impl_t *
vs_secbox_gateway() {
    return &_secbox_gateway;
}
