
#ifndef GATEWAY_SECBOX_KEYSTORAGE_FILE_H
#define GATEWAY_SECBOX_KEYSTORAGE_FILE_H

#include <stdint.h>
#include <stdio.h>

int
write_trustlist_file(const char *file_name, const uint8_t *data, uint16_t data_sz);
int
read_trustlist_file(const char *file_name, uint8_t *buf, size_t buf_sz, uint16_t *out_sz);
int
delete_trustlist_file(const char *file_name);
#endif // GATEWAY_SECBOX_KEYSTORAGE_FILE_H
