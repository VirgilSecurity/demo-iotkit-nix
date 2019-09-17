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

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(gateway VERSION 0.1.0 LANGUAGES C)

#
#	Gateway application
#
add_executable(gateway)

#
#   Options
#
set(GATEWAY_MANUFACTURE "0x89abcdef" CACHE STRING "Gateway manufacture code")
set(GATEWAY_MODEL "0x12345678" CACHE STRING "Gateway model code")

#
#	Header/Source files
#
target_sources(gateway
        PRIVATE

        # Headers
		${CMAKE_CURRENT_LIST_DIR}/include/event-flags.h
        ${CMAKE_CURRENT_LIST_DIR}/include/gateway.h
        ${CMAKE_CURRENT_LIST_DIR}/include/iot_mqtt.h
        ${CMAKE_CURRENT_LIST_DIR}/include/message_bin.h
        ${CMAKE_CURRENT_LIST_DIR}/include/fldt_implementation.h
        ${CMAKE_CURRENT_LIST_DIR}/include/test_update_thread.h
        ${CMAKE_CURRENT_LIST_DIR}/include/upd_http_retrieval_thread.h

        # Sources
        ${CMAKE_CURRENT_LIST_DIR}/src/main.c
        ${CMAKE_CURRENT_LIST_DIR}/src/cloud/https.c
        ${CMAKE_CURRENT_LIST_DIR}/src/communication/mqtt/message_bin.c
        ${CMAKE_CURRENT_LIST_DIR}/src/communication/mqtt/msg-bin-root-ca.c
        ${CMAKE_CURRENT_LIST_DIR}/src/communication/mqtt/iot_mqtt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/communication/sdmp/fldt_implementation.c
        ${CMAKE_CURRENT_LIST_DIR}/src/communication/sdmp/fldt_firmware.c
        ${CMAKE_CURRENT_LIST_DIR}/src/gateway/gateway.c
        ${CMAKE_CURRENT_LIST_DIR}/src/update/upd_http_retrieval_thread.c
        ${CMAKE_CURRENT_LIST_DIR}/src/update/update_hal.c
        ${CMAKE_CURRENT_LIST_DIR}/src/platform/platform-hal.c
        )

#
#	Definitions
#
target_compile_definitions(gateway
        PRIVATE
        TEST_UPDATE_MESSAGE="${TEST_UPDATE_MESSAGE}"
        SIMULATOR=$<BOOL:${GATEWAY_SIMULATOR}>
        SIM_FETCH_FIRMWARE=$<BOOL:${SIM_FETCH_FIRMWARE}>
		GATEWAY=1
		MANUFACTURE=${_manufacture}
		MODEL=${_model}
        )

#
#   Include directories
#
target_include_directories(gateway
        PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        )


#
#	Compile options
#
target_compile_options(gateway
        PRIVATE
        $<$<NOT:$<BOOL:${APPLE}>>:-Wno-format-truncation>
        )

#
#	Link libraries
#
target_link_libraries(gateway
        PRIVATE

		$<$<NOT:$<BOOL:${APPLE}>>:-Wl,--whole-archive>
		rpi-common
		$<$<NOT:$<BOOL:${APPLE}>>:-Wl,--no-whole-archive>

		curl
		aws-mqtt
		cloud
		update

        $<$<BOOL:${USE_ASAN}>:enable_asan_mode>
        $<$<BOOL:${USE_UBSAN}>:enable_ubsan_mode>

        enable_pedantic_mode
        )

#
# Format code
#
if(COMMAND add_clangformat)
	add_clangformat(gateway)
endif()
