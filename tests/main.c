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

#include <sys/stat.h>
#include <fts.h>
#include <errno.h>

#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/tests/tests.h>
#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/trust_list/trust_list.h>
#include <virgil/crypto/foundation/vscf_assert.h>
#include <update-config.h>

#include "hal/file_io_hal.h"
#include "hal/gateway_storage_hal.h"

static char _self_path[FILENAME_MAX];
/******************************************************************************/
static int
_recursive_delete(const char *dir) {
    int ret = 0;
    FTS *ftsp = NULL;
    FTSENT *curr;

    // Cast needed (in C) because fts_open() takes a "char * const *", instead
    // of a "const char * const *", which is only allowed in C++. fts_open()
    // does not modify the argument.
    char *files[] = {(char *)dir, NULL};

    // FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected behavior
    //                in multithreaded programs
    // FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files outside
    //                of the specified directory
    // FTS_XDEV     - Don't cross filesystem boundaries
    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    if (!ftsp) {
        VS_LOG_ERROR("%s: fts_open failed", dir);
        ret = -1;
        goto finish;
    }

    while ((curr = fts_read(ftsp))) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR:
            VS_LOG_TRACE("%s: fts_read error: %s", curr->fts_accpath, strerror(curr->fts_errno));
            break;

        case FTS_DC:
        case FTS_DOT:
        case FTS_NSOK:
            // Not reached unless FTS_LOGICAL, FTS_SEEDOT, or FTS_NOSTAT were
            // passed to fts_open()
            break;

        case FTS_D:
            // Do nothing. Need depth-first search, so directories are deleted
            // in FTS_DP
            break;

        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
            if (remove(curr->fts_accpath) < 0) {
                VS_LOG_ERROR("%s: Failed to remove", curr->fts_path);
                ret = -1;
            }
            break;
        }
    }

finish:
    if (ftsp) {
        fts_close(ftsp);
    }

    return ret;
}

/********************************************************************************/
static void
_remove_keystorage_dir() {
    char folder[FILENAME_MAX];

    if (!vs_gateway_get_keystorage_base_dir(folder)) {
        return;
    }
    _recursive_delete(folder);
}

/********************************************************************************/
static void
_assert_handler_fn(const char *message, const char *file, int line) {
    VS_LOG_ERROR("%s %s %u", message, file, line);
}

/******************************************************************************/
int
vs_update_install_prepare_space_hal(void) {
    char filename[FILENAME_MAX];

    VS_IOT_STRCPY(filename, _self_path);

    strcat(filename, ".new");
    remove(filename);
    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_update_install_append_data_hal(const void *data, uint16_t data_sz) {

    int res = VS_STORAGE_ERROR_GENERAL;
    char filename[FILENAME_MAX];
    FILE *fp = NULL;

    CHECK_NOT_ZERO(data, VS_STORAGE_ERROR_PARAMS);

    VS_IOT_STRCPY(filename, _self_path);

    strcat(filename, ".new");

    fp = fopen(filename, "a+b");
    if (fp) {

        if (1 != fwrite(data, data_sz, 1, fp)) {
            VS_LOG_ERROR("Unable to write %d bytes to the file %s. errno = %d (%s)",
                         data_sz,
                         filename,
                         errno,
                         strerror(errno));
        } else {
            res = VS_STORAGE_OK;
        }
        fclose(fp);
    }

    return res;
}

/********************************************************************************/
int
main(int argc, char *argv[]) {
    int res = 0;
    uint8_t mac[6];
    vs_storage_op_ctx_t storage_ctx;
    vs_gateway_get_storage_impl(&storage_ctx.impl);
    storage_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;

    memset(mac, 0, sizeof(mac));

    vs_logger_init(VS_LOGLEV_DEBUG);
    vscf_assert_change_handler(_assert_handler_fn);

    vs_hal_files_set_mac(mac);
    _remove_keystorage_dir();

    // Prepare TL storage
    vs_tl_init_storage();

    VS_LOG_INFO("[RPI] Start IoT rpi gateway tests");

    res = vs_tests_checks();

    storage_ctx.storage_ctx = vs_gateway_storage_init(vs_gateway_get_secbox_dir());
    if (NULL == storage_ctx.storage_ctx) {
        res += 1;
    }

    res += vs_secbox_test(&storage_ctx);

    storage_ctx.storage_ctx = vs_gateway_storage_init(vs_gateway_get_firmware_dir());
    if (NULL == storage_ctx.storage_ctx) {
        res += 1;
    }

    res += vs_update_test(&storage_ctx);

    VS_LOG_INFO("[RPI] Finish IoT rpi gateway tests");

    return res;
}
