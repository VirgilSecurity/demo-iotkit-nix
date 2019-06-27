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
#include <unistd.h>

#include <virgil/crypto/common/vsc_buffer.h>

#include <virgil/iot/initializer/communication/sdmp_initializer.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/tests/tests.h>
#include "communication/gateway_netif_plc.h"
#include "secbox_impl/gateway_secbox_impl.h"
// TODO : temporary disabled
#if 0
#include "iotelic/keystorage_tl.h"
#endif

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/hsm/hsm_interface.h>

/******************************************************************************/
uint32_t
app_crypto_entry() {
    uint32_t ret = 0;
// TODO : temporary disabled
#if 0
    const vs_netif_t *plc_netif = NULL;

    // Prepare secbox
    vs_secbox_configure_hal(vs_secbox_gateway());

    // Get PLC Network interface
    plc_netif = vs_hal_netif_plc();

    init_keystorage_tl();

    // Start SDMP protocol over PLC interface
    vs_sdmp_comm_start(plc_netif);

    sleep(300);
#endif

    return ret;
}
/******************************************************************************/

static bool
_read_mac_address(const char *arg, vs_mac_addr_t *mac) {
    int values[6];
    int i;

    if (6 ==
        sscanf(arg, "%x:%x:%x:%x:%x:%x%*c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for (i = 0; i < 6; ++i) {
            mac->bytes[i] = (uint8_t)values[i];
        }
        return true;
    }

    return false;
}

/******************************************************************************
static
void test_sign_verify(void){
    static const vs_iot_hsm_slot_e slot = VS_KEY_SLOT_STD_MTP_1;
    static const vs_hsm_keypair_type_e keypair_type = VS_KEYPAIR_EC_SECP256R1;
    static const vs_hsm_hash_type_e hash_type = VS_HASH_SHA_256;
    static const uint8_t tbs[] = {"Some message to be signed"};
    vs_hsm_keypair_type_e keypair_type_loaded;
    uint8_t hash[128];
    uint16_t hash_sz = sizeof(hash);
    uint8_t sign[128];
    uint16_t sign_sz = sizeof(sign);
    uint8_t pubkey[128];
    uint16_t pubkey_sz = sizeof(pubkey);

    VS_LOG_INFO("AES tests");

    VS_LOG_INFO("*** vs_hsm_keypair_create");
    if(VS_HSM_ERR_OK != vs_hsm_keypair_create(slot, keypair_type)){
        VS_LOG_ERROR("vs_hsm_keypair_create error");
        goto terminate;
    }

    VS_LOG_INFO("*** vs_hsm_hash_create");
    if(VS_HSM_ERR_OK != vs_hsm_hash_create(hash_type, tbs, sizeof(tbs), hash, hash_sz, &hash_sz)){
        VS_LOG_ERROR("vs_hsm_hash_create error");
        goto terminate;
    }

    VS_LOG_INFO("*** vs_hsm_ecdsa_sign");
    if(VS_HSM_ERR_OK != vs_hsm_ecdsa_sign(slot, hash_type, hash, sign, sign_sz, &sign_sz)){
        VS_LOG_ERROR("vs_hsm_ecdsa_sign error");
        goto terminate;
    }

    VS_LOG_INFO("*** vs_hsm_keypair_get_pubkey");
    if(VS_HSM_ERR_OK != vs_hsm_keypair_get_pubkey(slot, pubkey, pubkey_sz, &pubkey_sz, &keypair_type_loaded)){
        VS_LOG_ERROR("vs_hsm_ecdsa_sign error");
        goto terminate;
    }

    if(keypair_type != keypair_type_loaded){
        VS_LOG_ERROR("Unconsistent keypair types");
        goto terminate;
    }

    VS_LOG_INFO("*** vs_hsm_ecdsa_verify");
    if(VS_HSM_ERR_OK != vs_hsm_ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_type, hash, sign, sign_sz)){
        VS_LOG_ERROR("vs_hsm_ecdsa_verify error");
        goto terminate;
    }

//    pubkey[3] = ~pubkey[3];
//
//    if(VS_HSM_ERR_OK == vs_hsm_ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_type, hash, sign, sign_sz)){
//        VS_LOG_ERROR("vs_hsm_ecdsa_verify false positive because of corrupted public key");
//        goto terminate;
//    }
//
//    pubkey[3] = ~pubkey[3];


    sign[3] = ~sign[3];

    if(VS_HSM_ERR_OK == vs_hsm_ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_type, hash, sign, sign_sz)){
        VS_LOG_ERROR("vs_hsm_ecdsa_verify false positive because of corrupted signature");
        goto terminate;
    }

    sign[3] = ~sign[3];

    hash[3] = ~hash[3];

    if(VS_HSM_ERR_OK == vs_hsm_ecdsa_verify(keypair_type, pubkey, pubkey_sz, hash_type, hash, sign, sign_sz)){
        VS_LOG_ERROR("vs_hsm_ecdsa_verify false positive because of corrupted signature");
        goto terminate;
    }

terminate:;
}
*/

/******************************************************************************/
int
main(int argc, char *argv[]) {
    // Setup forced mac address
    vs_mac_addr_t forced_mac_addr;
    int result;

    vs_logger_init(VS_LOGLEV_DEBUG);
    result = virgil_iot_sdk_tests();

    if (argc == 2 && _read_mac_address(argv[1], &forced_mac_addr)) {
        vs_hal_netif_plc_force_mac(forced_mac_addr);
    } else {
        printf("\nERROR: need to set MAC address of simulated device\n\n");
        return -1;
    }

    // Start app
    app_crypto_entry();
    return result;
}

/******************************************************************************/
