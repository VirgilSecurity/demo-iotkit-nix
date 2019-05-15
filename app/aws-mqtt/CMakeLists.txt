cmake_minimum_required (VERSION 3.11)

project(aws-mqtt VERSION 0.1.0 LANGUAGES C)

set(AWS_MQTT_LIB aws-mqtt)

# file folders
set(AWS_MQTT_ROOT     "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(AWS_MQTT_SOURCE   "${AWS_MQTT_ROOT}/src")
set(AWS_MQTT_INCLUDE  "${AWS_MQTT_ROOT}/include")
set(AWS_MQTT_EXT_LIBS  "${AWS_MQTT_ROOT}/external_libs")
set(AWS_MQTT_PLATFORM  "${AWS_MQTT_ROOT}/platform/linux")
set (MBED_TLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libsim/mbedtls-2.4.0)

#
#   aws-mqtt core sources
#
file (GLOB_RECURSE AWS_MQTT_LIST_SRC "${AWS_MQTT_SOURCE}/*.c")
set (AWS_MQTT_SOURCE_FILES
        ${AWS_MQTT_LIST_SRC}
        "${AWS_MQTT_EXT_LIBS}/jsmn/jsmn.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform/common/timer.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform/mbedtls/network_mbedtls_wrapper.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform/pthread/threads_pthread_wrapper.c"
        )

add_library(${AWS_MQTT_LIB}
        ${AWS_MQTT_SOURCE_FILES}
        )

target_include_directories (${AWS_MQTT_LIB}
        PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${AWS_MQTT_INCLUDE}"
        "${AWS_MQTT_EXT_LIBS}/jsmn"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform/mbedtls"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform/pthread"
        "${MBED_TLS_DIR}/include"
        )


