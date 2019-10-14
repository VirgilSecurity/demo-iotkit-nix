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

#ifndef IOT_RPI_HAL_H
#define IOT_RPI_HAL_H

#include <stdint.h>
#include <arpa/inet.h>

#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/firmware/firmware.h>

extern char *self_path;

int
vs_rpi_hal_update(const char *manufacture_id_str, const char *device_type_str, int argc, char *argv[]);

void
vs_rpi_hal_sleep_until_stop(void);

vs_status_e
vs_rpi_start(const char *devices_dir,
             const char *app_file,
             vs_mac_addr_t forced_mac_addr,
             const char *manufacture_id,
             const char *device_type,
             const uint32_t device_roles,
             bool is_initializer);

void
vs_rpi_restart(void);

int
vs_load_own_firmware_descriptor(const char *manufacture_id_str,
                                const char *device_type_str,
                                vs_storage_op_ctx_t *op_ctx,
                                vs_firmware_descriptor_t *descriptor);

//-----------------------------------

const char *
vs_rpi_trustlist_dir(void);

const char *
vs_rpi_firmware_dir(void);

const char *
vs_rpi_slots_dir(void);

void
vs_rpi_create_data_array(uint8_t *dst, const char *src, size_t elem_buf_size);

void
vs_rpi_get_serial(vs_device_serial_t serial, vs_mac_addr_t mac);


void
vs_rpi_print_title(const char *devices_dir,
                   const char *app_file,
                   const char *manufacture_id_str,
                   const char *device_type_str);

vs_status_e
vs_rpi_prepare_storage(const char *devices_dir, vs_mac_addr_t device_mac);

vs_netif_t *
vs_rpi_create_netif_impl(vs_mac_addr_t forced_mac_addr);

vs_status_e
vs_rpi_create_storage_impl(vs_storage_op_ctx_t *storage_impl, const char *base_dir, size_t file_size_max);


#endif // IOT_RPI_HAL_H
