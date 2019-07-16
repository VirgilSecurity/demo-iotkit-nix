/**
 * Copyright (C) 2017 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file https.h
 * @brief https wrapper.
 */

#ifndef INCLUDE_HTTPS_H_
#define INCLUDE_HTTPS_H_
#include <stdint.h>
#include <stddef.h>

#define HTTPS_INPUT_BUFFER_SIZE (8192)

#define HTTPS_RET_CODE_ERROR_OPEN_SESSION 1000
#define HTTPS_RET_CODE_ERROR_PREPARE_REQ 1001
#define HTTPS_RET_CODE_ERROR_SEND_REQ 1002
#define HTTPS_RET_CODE_ERROR_GET 1003
#define HTTPS_RET_CODE_OK 200

typedef int http_session_t;

/* Request methods */
typedef enum {
    HTTP_OPTIONS, /* request to server for communication  options */
    HTTP_GET,     /* retrieve information */
    HTTP_HEAD,    /* get meta-info */
    HTTP_POST,    /* request to accept new sub-ordinate of resource */
    HTTP_PUT,     /* modify or create new resource referred to by URI */
    HTTP_PATCH,   /* modify or create new resource referred
                   * to by URI */
    HTTP_DELETE,  /* delete the resource */
    HTTP_TRACE,   /* echo */
    HTTP_CONNECT, /* do we need this  ? */
} http_method_t;

uint16_t
https(http_method_t type,
      const char *url,
      const char *authorization,
      const char *data,
      size_t data_size,
      char *out_data,
      size_t *in_out_size);
#endif /* INCLUDE_HTTPS_H_ */
