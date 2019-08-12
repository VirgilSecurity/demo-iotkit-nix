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
#include <virgil/iot/protocols/sdmp/fldt.h>
#include <sdmp_app.h>
#include <communication/gateway_netif_plc.h>

#define PLC_CMD_PRIORITY 0

/******************************************************************************/
int
vs_sdmp_comm_start_thread(void) {

    CHECK_RET(!vs_sdmp_init(vs_hal_netif_plc()), -1, "Unable to initialize SDMP over PLC interface");

    CHECK_RET(!vs_sdmp_register_service(vs_sdmp_fwdt_service()), -2, "Unable to register FWDT service");

    CHECK_RET(!vs_sdmp_fwdt_configure_hal(vs_fwdt_impl()), -3, "Unable to configure FWDT HAL");

    vs_sdmp_fwdt_manifest_t manifest = {.some_data = {0x01, 0x02, 0x03, 0x04}};
    vs_sdmp_fwdt_mfst_list_t lst = {.count = 0};
    vs_sdmp_fwdt_broadcast_manifest(vs_hal_netif_plc(), &manifest, &lst, 1000);

    return 0;
}

/******************************************************************************/
