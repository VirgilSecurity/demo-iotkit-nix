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

project(rpi_gw_lib VERSION 0.1.0 LANGUAGES C)

set(RPI_GW_LIB rpi_gw)


#
#   Source code
#
set(RPI_GW_SRC
		src/base64/base64.c
		src/communication/gateway_netif_plc.c
		src/secbox_impl/gateway_secbox_impl.c
		src/helpers/file-system.c
		src/hal/crypto_hal.c
		src/hal/file_io_hal.c
		src/hal/keypair_hal.c
		src/hal/hal.c
		)

#
#   RaspberryPi gateway library
#
add_library(${RPI_GW_LIB}
		${RPI_GW_SRC}
		)

target_link_libraries(${RPI_GW_LIB}
		hsm
		logger
		foundation
		converters
		)
#
#   -Wall -Werror
#
set_target_properties(${RPI_GW_LIB} PROPERTIES COMPILE_FLAGS "-Wall -Werror -Wno-multichar")

#
#   Common include directories
#

set (VIRGIL_SDK_DIR "${CMAKE_SOURCE_DIR}/ext/virgil-iot-sdk")
target_include_directories(${RPI_GW_LIB}
		PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include
		${VIRGIL_SDK_DIR}/protocols/sdmp/include
		${VIRGIL_SDK_DIR}/secbox/include
		)

#
# Format code
#
if(COMMAND add_clangformat)
	add_clangformat(${RPI_GW_LIB})
endif()