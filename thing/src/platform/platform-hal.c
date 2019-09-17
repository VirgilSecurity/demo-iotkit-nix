////  Copyright (C) 2015-2019 Virgil Security, Inc.
////
////  All rights reserved.
////
////  Redistribution and use in source and binary forms, with or without
////  modification, are permitted provided that the following conditions are
////  met:
////
////      (1) Redistributions of source code must retain the above copyright
////      notice, this list of conditions and the following disclaimer.
////
////      (2) Redistributions in binary form must reproduce the above copyright
////      notice, this list of conditions and the following disclaimer in
////      the documentation and/or other materials provided with the
////      distribution.
////
////      (3) Neither the name of the copyright holder nor the names of its
////      contributors may be used to endorse or promote products derived from
////      this software without specific prior written permission.
////
////  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
////  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
////  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
////  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
////  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
////  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
////  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
////  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
////  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
////  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
////  POSSIBILITY OF SUCH DAMAGE.
////
////  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//
//#include <string.h>
//#include <global-hal.h>
//#include <gateway.h>
//#include <virgil/iot/cloud/cloud.h>
//#include <virgil/iot/provision/provision.h>
//
//#define GW_MANUFACTURE_ID \
//    { 'V', 'R', 'G', 'L' }
//#define GW_DEVICE_TYPE \
//    { 'C', 'f', '0', '1' }
//#define GW_APP_TYPE \
//    { 'A', 'P', 'P', '0' }
//
//// TODO: Need to use real descriptor, which can be obtain from footer of self image
// static vs_firmware_descriptor_t _descriptor = {
//        .info.manufacture_id = GW_MANUFACTURE_ID,
//        .info.device_type = GW_DEVICE_TYPE,
//        .info.version.app_type = GW_APP_TYPE,
//        .info.version.major = 0,
//        .info.version.minor = 1,
//        .info.version.patch = 3,
//        .info.version.dev_milestone = 'm',
//        .info.version.dev_build = 0,
//        .info.version.timestamp = 0,
//        .padding = 0,
//        .chunk_size = 256,
//        .firmware_length = 2097152,
//        .app_size = 2097152,
//};
//
///******************************************************************************/
// void
// vs_global_hal_get_udid_of_device(uint8_t udid[SERIAL_SIZE]) {
//    memcpy(udid, get_gateway_ctx()->udid_of_device, SERIAL_SIZE);
//}
//
///******************************************************************************/
// const vs_firmware_descriptor_t *
// vs_global_hal_get_own_firmware_descriptor(void) {
//    return &_descriptor;
//}