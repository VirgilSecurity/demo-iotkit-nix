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

#include <string.h>
#include <stdio.h>
#include "helpers/input-params.h"

/******************************************************************************/
static char *
_get_commandline_arg(int argc, char *argv[], const char *shortname, const char *longname) {
    size_t pos;

    if (!(argv && shortname && *shortname && longname && *longname)) {
        return NULL;
    }

    for (pos = 0; pos < argc; ++pos) {
        if (!strcmp(argv[pos], shortname) && (pos + 1) < argc)
            return argv[pos + 1];
        if (!strcmp(argv[pos], longname) && (pos + 1) < argc)
            return argv[pos + 1];
    }

    return NULL;
}

/******************************************************************************/
static bool
_read_mac_address(const char *arg, vs_mac_addr_t *mac) {
    unsigned int values[6];
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

/******************************************************************************/
vs_status_e
vs_process_commandline_params(int argc, char *argv[], struct in_addr *plc_sim_addr, vs_mac_addr_t *forced_mac_addr) {
    static const char *PLC_SIM_ADDRESS_SHORT = "-a";
    static const char *PLC_SIM_ADDRESS_FULL = "--address";
    static const char *MAC_SHORT = "-m";
    static const char *MAC_FULL = "--mac";
    char *mac_str;
    char *plc_sim_addr_str;

    if (!argv || !argc || !plc_sim_addr || !forced_mac_addr) {
        printf("Wrong input parameters.");
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    mac_str = _get_commandline_arg(argc, argv, MAC_SHORT, MAC_FULL);
    plc_sim_addr_str = _get_commandline_arg(argc, argv, PLC_SIM_ADDRESS_SHORT, PLC_SIM_ADDRESS_FULL);

    // Check input parameters
    if (!mac_str || !plc_sim_addr_str) {
        printf("usage: gateway %s/%s <PLC simulator IP> %s/%s <forces MAC address>\n",
               PLC_SIM_ADDRESS_SHORT,
               PLC_SIM_ADDRESS_FULL,
               MAC_SHORT,
               MAC_FULL);
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    if (!inet_aton(plc_sim_addr_str, plc_sim_addr)) {
        printf("Incorrect PLC simulator IP address \"%s\" was specified", plc_sim_addr_str);
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    if (!_read_mac_address(mac_str, forced_mac_addr)) {
        printf("Incorrect forced MAC address \"%s\" was specified", mac_str);
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    return VS_CODE_OK;
}
