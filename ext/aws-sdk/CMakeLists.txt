cmake_minimum_required (VERSION 3.11)

project(aws-mqtt VERSION 0.1.0 LANGUAGES C)

# file folders
set(AWS_MQTT_ROOT     "${CMAKE_CURRENT_LIST_DIR}/aws-iot-device-sdk-embedded-C")
set(AWS_MQTT_SOURCE   "${AWS_MQTT_ROOT}/src")
set(AWS_MQTT_INCLUDE  "${AWS_MQTT_ROOT}/include")
set(AWS_MQTT_EXT_LIBS  "${AWS_MQTT_ROOT}/external_libs")
set(AWS_MQTT_PLATFORM  "${AWS_MQTT_ROOT}/platform/linux")

# Include and build external libraries
include (${CMAKE_CURRENT_LIST_DIR}/../virgil-iot-sdk/cmake/virgil_depends.cmake)

virgil_depends (
        PACKAGE_NAME "MbedTLS"
        CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libs_ext/mbedtls"
        CMAKE_ARGS "${MBEDTLS_CMAKE_ARGS}"
)
virgil_find_package (MbedTLS 2.4)

add_library(aws-mqtt)

#
#   aws-mqtt core sources
#
file (GLOB_RECURSE AWS_MQTT_LIST_SRC "${AWS_MQTT_SOURCE}/*.c")

target_sources(aws-mqtt
        PRIVATE
        ${AWS_MQTT_LIST_SRC}
        "${AWS_MQTT_EXT_LIBS}/jsmn/jsmn.c"
        "${CMAKE_CURRENT_LIST_DIR}/platform/common/timer.c"
        "${CMAKE_CURRENT_LIST_DIR}/platform/mbedtls/network_mbedtls_wrapper.c"
        "${CMAKE_CURRENT_LIST_DIR}/platform/pthread/threads_pthread_wrapper.c"
        )

target_link_libraries(aws-mqtt
        mbedtls::mbedcrypto
        mbedtls::ed25519
        )

target_include_directories (aws-mqtt
        PUBLIC
        "${CMAKE_CURRENT_LIST_DIR}"
        "${AWS_MQTT_INCLUDE}"
        "${AWS_MQTT_EXT_LIBS}/jsmn"
        "${CMAKE_CURRENT_LIST_DIR}/platform/common"
        "${CMAKE_CURRENT_LIST_DIR}/platform/mbedtls"
        "${CMAKE_CURRENT_LIST_DIR}/platform/pthread"
        )


