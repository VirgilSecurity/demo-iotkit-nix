
#ifndef GATEWAY_SECBOX_KEYSTORAGE_FILE_H
#define GATEWAY_SECBOX_KEYSTORAGE_FILE_H

#include <stdint.h>
#include <stdio.h>
#include "iotelic/keystorage_tl.h"

#define TL_HEADER_FILENAME_PREFIX "tl_header"
#define TL_KEY_FILENAME_PREFIX "tl_key"
#define TL_FOOTER_FILENAME_PREFIX "tl_footer"

#define PBR_FILENAME_PREFIX "pbr"
#define PBA_FILENAME_PREFIX "pba"
#define PBT_FILENAME_PREFIX "pbt"
#define PBF_FILENAME_PREFIX "pbf"
#define SGN_FILENAME_PREFIX "sgn"

#define OWN_PRIVATE_KEY_FILENAME "own_priv_key"
void
prepare_keystorage_folder(char folder[FILENAME_MAX]);
bool
write_keystorage_file(const char *folder, const char *file_name, const uint8_t *data, size_t data_sz);
bool
read_keystorage_file(const char *folder, const char *file_name, uint8_t *buf, size_t buf_sz, size_t *out_sz);
bool
write_tl_header_file(tl_context_t *ctx, const trust_list_header_t *tl_header);
bool
read_tl_header_file(tl_context_t *ctx, trust_list_header_t *tl_header);
bool
remove_keystorage_tl_header_file(tl_context_t *ctx);
bool
write_tl_key_file(tl_context_t *ctx, size_t key_id, const trust_list_pub_key_t *key);
bool
read_tl_key_file(tl_context_t *ctx, size_t key_id, trust_list_pub_key_t *key);
bool
remove_keystorage_tl_key_file(tl_context_t *ctx, tl_key_handle handle);
bool
write_tl_footer_file(tl_context_t *ctx, const trust_list_footer_t *footer);
bool
read_tl_footer_file(tl_context_t *ctx, trust_list_footer_t *footer);
bool
remove_keystorage_tl_footer_file(tl_context_t *ctx);

#endif // GATEWAY_SECBOX_KEYSTORAGE_FILE_H
