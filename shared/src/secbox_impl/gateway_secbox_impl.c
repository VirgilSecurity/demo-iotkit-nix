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
#include <stdint.h>
#include <stdio.h>

#include <virgil/iot/secbox/secbox.h>

#include "gateway_macro.h"
#include "secbox_impl/file-system.h"

static int
vs_secbox_gateway_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, uint16_t data_sz);
static int
vs_secbox_gateway_save(vs_secbox_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz);
static int
vs_secbox_gateway_del(vs_secbox_element_info_t *element_info);
static int
vs_secbox_gateway_init(void);

static vs_secbox_hal_impl_t _secbox_gateway = {.save = vs_secbox_gateway_save,
                                               .load = vs_secbox_gateway_load,
                                               .del = vs_secbox_gateway_del,
                                               .init = vs_secbox_gateway_init};

static char folder[FILENAME_MAX];

/******************************************************************************/
static int
vs_secbox_gateway_init(void) {

    prepare_keystorage_folder(folder);

    return GATEWAY_OK;
}

/******************************************************************************/
static void
_make_path(char *filename, uint16_t filename_sz, vs_secbox_element_info_t *element_info) {
    assert(filename);
    assert(filename_sz);
    assert(element_info);

    snprintf(
            filename, filename_sz, "%04X-%04X-%04X", element_info->storage_type, element_info->id, element_info->index);
}

/******************************************************************************/
static int
vs_secbox_gateway_save(vs_secbox_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz) {
    int res;
    char filename[FILENAME_MAX];

    assert(element_info);
    assert(in_data);
    assert(data_sz);

    _make_path(filename, sizeof(filename), element_info);

    res = write_keystorage_file(folder, filename, in_data, data_sz) ? GATEWAY_OK : GATEWAY_ERROR;

    return res;
}

/******************************************************************************/
static int
vs_secbox_gateway_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, uint16_t data_sz) {
    char filename[FILENAME_MAX];
    int res;

    assert(element_info);
    assert(out_data);
    assert(data_sz);

    _make_path(filename, sizeof(filename), element_info);

    res = read_keystorage_file(folder, filename, out_data, data_sz, &data_sz) ? GATEWAY_OK : GATEWAY_ERROR;

    return res;
}

/******************************************************************************/
static int
vs_secbox_gateway_del(vs_secbox_element_info_t *element_info) {
    assert(element_info);

    return GATEWAY_ERROR;
}

/******************************************************************************/
const vs_secbox_hal_impl_t *
vs_secbox_gateway() {
    return &_secbox_gateway;
}
