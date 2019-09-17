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

#ifndef RPI_SDMP_FLDT_IMPLEMENTATION_H
#define RPI_SDMP_FLDT_IMPLEMENTATION_H

#include <global-hal.h>
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <virgil/iot/update/update.h>

vs_mac_addr_t vs_fldt_gateway_mac;

vs_fldt_ret_code_e
vs_fldt_add_fw_filetype(const vs_fldt_file_type_t *file_type);

vs_fldt_ret_code_e
vs_fldt_add_filetype(const vs_fldt_file_type_t *file_type);

vs_fldt_ret_code_e
vs_fldt_init(const vs_mac_addr_t *gateway_mac);

vs_fldt_ret_code_e
vs_fldt_new_firmware_available(vs_firmware_info_t *firmware_info);

void
vs_fldt_fw_init(void);

void
vs_fldt_destroy(void);

#endif // RPI_SDMP_FLDT_IMPLEMENTATION_H