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
#include <trust_list-config.h>

#include "hal/storage/rpi-file-io.h"
#include "hal/storage/rpi-storage-hal.h"
#include "hal/rpi-global-hal.h"

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

    if (!vs_rpi_get_keystorage_base_dir(folder)) {
        return;
    }
    _recursive_delete(folder);
}

/********************************************************************************/
static void
_assert_handler_fn(const char *message, const char *file, int line) {
    VS_LOG_ERROR("%s %s %u", message, file, line);
}

/********************************************************************************/
int
main(int argc, char *argv[]) {
    int res = 0;
    uint8_t mac[6];
    self_path = argv[0];
    vs_storage_op_ctx_t secbox_ctx;
    vs_storage_op_ctx_t tl_ctx;

    memset(mac, 0, sizeof(mac));

    vs_logger_init(VS_LOGLEV_DEBUG);
    vscf_assert_change_handler(_assert_handler_fn);

    vs_hal_files_set_dir("test");
    vs_hal_files_set_mac(mac);
    _remove_keystorage_dir();

    // Prepare TL storage
    vs_rpi_get_storage_impl(&tl_ctx.impl);
    tl_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_trust_list_dir());
    tl_ctx.file_sz_limit = VS_TL_STORAGE_MAX_PART_SIZE;
    vs_tl_init(&tl_ctx);

    VS_LOG_INFO("[RPI] Start IoT tests");

    res = vs_tests_checks(false); //, VS_FLDT_FIRMWARE, VS_FLDT_TRUSTLIST, VS_FLDT_OTHER);

    vs_rpi_get_storage_impl(&secbox_ctx.impl);
    secbox_ctx.file_sz_limit = VS_MAX_FIRMWARE_UPDATE_SIZE;
    secbox_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_secbox_dir());
    if (NULL == secbox_ctx.storage_ctx) {
        res += 1;
    }

    res += vs_secbox_test(&secbox_ctx);

    secbox_ctx.storage_ctx = vs_rpi_storage_init(vs_rpi_get_firmware_dir());
    if (NULL == secbox_ctx.storage_ctx) {
        res += 1;
    }

    res += vs_firmware_test(&secbox_ctx);

    VS_LOG_INFO("[RPI] Finish IoT rpi gateway tests");

    return res;
}
