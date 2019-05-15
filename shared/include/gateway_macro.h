//
// Created by Maxim Grigoryev on 2019-04-10.
//

#ifndef GATEWAY_MACRO_H
#define GATEWAY_MACRO_H

#include <string.h>

#define GATEWAY_OK 0
#define GATEWAY_ERROR (-1)

#define IOT_INFO(...)                                                                                                  \
    do {                                                                                                               \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
    } while (0)

#define IOT_WARN(...)                                                                                                  \
    do {                                                                                                               \
        printf("WARN:  %s L#%d ", __func__, __LINE__);                                                                 \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
    } while (0)

#define IOT_ERROR(...)                                                                                                 \
    do {                                                                                                               \
        printf("ERROR: %s L#%d ", __func__, __LINE__);                                                                 \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
    } while (0)

#endif // GATEWAY_MACRO_H
