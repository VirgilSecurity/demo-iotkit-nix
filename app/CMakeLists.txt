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

project(virgil-iot-gateway-app VERSION 0.1.0 LANGUAGES C)

add_executable(virgil-iot-gateway-app)
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

target_sources(virgil-iot-gateway-app
		PRIVATE
		${GW_PLATFORM_APP_SRC}
		src/main.c
		src/cloud/https.c
		src/communication/mqtt/message_bin.c
		src/communication/mqtt/msg-bin-root-ca.c
		src/communication/mqtt/iot_mqtt.c
		src/communication/sdmp/sdmp_app.c
		src/gateway/gateway.c
		src/platform/os.c
		src/update/upd_http_retrieval_thread.c
		src/update/update_hal.c
		src/platform/platform-hal.c
		"$<$<BOOL:${GATEWAY_SIMULATOR}>:src/test_update_thread.c>"
		)

	target_compile_definitions(virgil-iot-gateway-app
			PRIVATE
			TEST_UPDATE_MESSAGE="${TEST_UPDATE_MESSAGE}"
			SIMULATOR=$<BOOL:${GATEWAY_SIMULATOR}>
			SIM_FETCH_FIRMWARE=$<BOOL:${SIM_FETCH_FIRMWARE}>
			)

#
#   -Wall -Werror
#
target_compile_options(virgil-iot-gateway-app
		PRIVATE
		-Wall
		-Werror
		-Wno-multichar
		)

#
#   Include directories
#
target_include_directories(virgil-iot-gateway-app
		PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/include
		PUBLIC
		${CMAKE_CURRENT_LIST_DIR}/include/platform
		)

#
#	Link libraries
#
if(UNIX AND NOT APPLE)
	target_compile_options(virgil-iot-gateway-app
			PRIVATE
			-Wno-error=format-truncation
			)

	target_link_libraries(virgil-iot-gateway-app
			-Wl,--whole-archive rpi_gw_shared hsm provision -Wl,--no-whole-archive
			)
else()
	target_link_libraries(virgil-iot-gateway-app rpi_gw_shared)
endif()

target_link_libraries (virgil-iot-gateway-app
		curl
		freertos
		aws-mqtt
		cloud
		macros
		update
		)
