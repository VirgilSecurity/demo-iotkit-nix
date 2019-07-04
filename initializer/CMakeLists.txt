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

project(virgil-iot-gateway-initializer VERSION 0.1.0 LANGUAGES C)

#
#	MCU Initializer
#
add_executable(virgil-iot-gateway-initializer
		${GW_INITIALIZER_SRC}
		)

#
#	Define variables
#
set (IOT_GW_INITIALIZER virgil-iot-gateway-initializer)
set (BIN_FILE ${IOT_GW_INITIALIZER}.bin)

#
#	Header/Source files
#
target_sources(virgil-iot-gateway-initializer
		PRIVATE
		# Headers
		include/virgil/iot/initializer/communication/sdmp_initializer.h
		include/virgil/iot/initializer/sdmp/prvs_implementation.h

		# Sources
		src/main.c
		src/communication/sdmp_initializer.c
		src/sdmp/prvs_implementation.c

		# TODO : need to move to the correct place or merge to some other file
		src/iot_pkt_api.h
		src/iot_plc_api.h
		src/sim_plc.h
		src/sim_plc.c

		)

#
#   -Wall -Werror
#
target_compile_options(virgil-iot-gateway-initializer
		PRIVATE
		-Wall
		-Werror
		-Wno-multichar
		)

#
#   Include directories
#
target_include_directories(virgil-iot-gateway-initializer
		PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include
		${CMAKE_CURRENT_SOURCE_DIR}/../shared/include
		${CMAKE_CURRENT_SOURCE_DIR}/../../ap/security-sdk/protocols/sdmp/include
		${CMAKE_CURRENT_SOURCE_DIR}/../../ap/security-sdk/secbox/include
		${CMAKE_CURRENT_SOURCE_DIR}/../../sp/crypto/inc
		)

#
#	Link libraries
#
target_link_libraries (virgil-iot-gateway-initializer
		foundation
		sdmp
		secbox
		rpi_gw_shared
		logger
		)

#
#	Add cmake test
#
add_test (
		NAME virgil-iot-gateway-initializer
		COMMAND "${CMAKE_CURRENT_BINARY_DIR}/virgil-iot-gateway-initializer"
)