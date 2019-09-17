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

#include <virgil/iot/protocols/sdmp/fldt.h>
#include <fldt_implementation.h>
#include <limits.h>
#include <hal/rpi-global-hal.h>

/******************************************************************************/
static void
_got_file(const vs_fldt_file_version_t *prev_file_ver,
          const vs_fldt_file_version_t *cur_file_ver,
          const vs_mac_addr_t *gateway,
          bool successfully_updated) {
    char prev_file_ver_descr[FLDT_FILEVER_BUF];
    char cur_file_ver_descr[FLDT_FILEVER_BUF];

    VS_IOT_ASSERT(prev_file_ver);
    VS_IOT_ASSERT(cur_file_ver);
    VS_IOT_ASSERT(gateway);

    switch (cur_file_ver->file_type.file_type_id) {
    case VS_UPDATE_FIRMWARE:
        VS_LOG_INFO("New firmware %s instead of %s downloaded from gateway " FLDT_GATEWAY_TEMPLATE ", %s",
                    vs_fldt_file_version_descr(cur_file_ver_descr, cur_file_ver),
                    vs_fldt_file_version_descr(prev_file_ver_descr, prev_file_ver),
                    FLDT_GATEWAY_ARG(*gateway),
                    successfully_updated ? "successfully installed" : "did not installed successfully");
        vs_rpi_restart();
        break;

    default:
        assert(false && "File type is not supported");
    }
}

/******************************************************************************/
vs_fldt_ret_code_e
vs_fldt_init(void) {
    vs_fldt_ret_code_e fldt_ret_code;

    VS_LOG_DEBUG("[FLDT] Initialization");

    FLDT_CHECK(vs_fldt_init_client(_got_file), "Unable to initialize FLDT");
    FLDT_CHECK(vs_fldt_firmware_init(), "Unable to add firmware file type");

    VS_LOG_DEBUG("[FLDT] Successfully initialized");

    return VS_FLDT_ERR_OK;
}

/******************************************************************************/
void
vs_fldt_destroy(void) {

    vs_fldt_destroy_client();

    VS_LOG_DEBUG("[FLDT] Successfully destroyed");
}
