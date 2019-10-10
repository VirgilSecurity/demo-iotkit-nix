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

#include <stdio.h>

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/prvs/prvs-server.h>
#include <virgil/iot/status_code/status_code.h>
#include <hal/rpi-global-hal.h>

#include "helpers/input-params.h"

/******************************************************************************/
int
vs_impl_own_firmware_descriptor(void *descriptor) {
    assert(descriptor);
    CHECK_NOT_ZERO_RET(descriptor, -1);

    memset(descriptor, 0, sizeof(vs_firmware_descriptor_t));

    return 0;
}

/******************************************************************************/
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    vs_mac_addr_t forced_mac_addr;
    vs_storage_op_ctx_t tl_ctx;
    vs_status_e ret_code;
#if GATEWAY
    const char *base_dir = "gateway";
    uint32_t roles = VS_SDMP_DEV_GATEWAY;
#else
    const char *base_dir = "thing";
    uint32_t roles = VS_SDMP_DEV_THING;
#endif

    if (0 != vs_process_commandline_params(argc, argv, &forced_mac_addr)) {
        return -1;
    }

    STATUS_CHECK_RET(vs_rpi_start(base_dir,
                                  argv[0],
                                  forced_mac_addr,
                                  &tl_ctx,
                                  NULL,
                                  (const char *)MANUFACTURE_ID,
                                  (const char *)DEVICE_MODEL,
                                  roles,
                                  true),
                     "Cannot start initializer");

    STATUS_CHECK_RET(vs_sdmp_register_service(vs_sdmp_prvs_server()), "Cannot register PRVS service");

    // Sleep until CTRL_C
    vs_rpi_hal_sleep_until_stop();

    VS_LOG_INFO("\n\n\nTerminating application ...");

    vs_sdmp_deinit();

    vs_tl_deinit();

    return 0;
}

/******************************************************************************/
