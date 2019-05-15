#   Copyright (C) 2015-2019 Virgil Security Inc.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#       (1) Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#       (2) Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#       (3) Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
#   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#   POSSIBILITY OF SUCH DAMAGE.
#
#   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

cmake_minimum_required (VERSION 3.11 FATAL_ERROR)

#
#	Define variables
#
set (IOT_GW_APP virgil-iot-gateway-app)
set (BIN_FILE ${IOT_GW_APP}.bin)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/aws-mqtt)

#
#	Source files
#
if (APPLE)
	set (GW_PLATFORM_APP_SRC
			${CMAKE_CURRENT_SOURCE_DIR}/src/platform/mac/hardware.c
			)
elseif(UNIX)
	set (GW_PLATFORM_APP_SRC
			${CMAKE_CURRENT_SOURCE_DIR}/src/platform/unix/hardware.c
			)
endif ()

set (GW_APP_SRC
		${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/platform/os.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/communication/sdmp/sdmp_app.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/communication/mqtt/message_bin.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/communication/mqtt/msg-bin-root-ca.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/communication/mqtt/iot_mqtt.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/cloud/https.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/cloud/cloud.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/gateway/gateway.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/update/fw_upgrade.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/update/tl_update.c
		${CMAKE_CURRENT_SOURCE_DIR}/src/update/upd_http_retrieval_thread.c
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/src/communication/gateway_netif_plc.c
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/src/secbox_impl/gateway_secbox_impl.c
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/src/secbox_impl/secbox_files.c
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/src/secbox_impl/gateway_keystorage_tl.c
		src/json/json_parser.c
		src/json/json_generator.c
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/src/base64/base64.c
		)

#
#	MCU Initializer
#
add_executable(${IOT_GW_APP}
		${GW_APP_SRC}
		${GW_PLATFORM_APP_SRC}
		)

#
#   -Wall -Werror
#
set_target_properties(${IOT_GW_APP} PROPERTIES COMPILE_FLAGS "-Wall -Werror -Wno-multichar")

#
#   Include directories
#
target_include_directories(${IOT_GW_APP}
		PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include
		${CMAKE_CURRENT_SOURCE_DIR}/aws-mqtt/lib/external_libs/jsmn/
		${CMAKE_CURRENT_SOURCE_DIR}/aws-mqtt/lib/include
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/include
		${CMAKE_CURRENT_SOURCE_DIR}/../../ap/security-sdk/protocols/sdmp/include
		${CMAKE_CURRENT_SOURCE_DIR}/../../ap/security-sdk/secbox/include
		${CMAKE_CURRENT_SOURCE_DIR}/../../sp/crypto/inc
		${SIM_INCLUDE_DIR}
		)

#
#	Link libraries
#
target_link_libraries (${IOT_GW_APP}
		foundation
		mbedtls_sp
		mbedx509_sp
		sdmp
		secbox
		freertos-unix
		aws-mqtt
		)

#
#	Add cmake test
#
add_test (
		NAME ${IOT_GW_APP}
		COMMAND "${CMAKE_CURRENT_BINARY_DIR}/${IOT_GW_APP}"
)