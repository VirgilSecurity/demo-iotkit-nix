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

project(rpi-common VERSION 0.1.0 LANGUAGES C)

#
#   RaspberryPi common code library
#
add_library(rpi-common)

#
#	Header/Source files
#
target_sources(rpi-common
		PRIVATE

		#	Headers
		${CMAKE_CURRENT_LIST_DIR}/include/hal/netif/rpi-plc-sim.h
		${CMAKE_CURRENT_LIST_DIR}/include/hal/netif/rpi-udp-broadcast.h
		${CMAKE_CURRENT_LIST_DIR}/include/hal/storage/rpi-file-io.h
		${CMAKE_CURRENT_LIST_DIR}/include/hal/rpi-global-hal.h
		${CMAKE_CURRENT_LIST_DIR}/include/threads/event-group-bits.h

		#	Sources
		${CMAKE_CURRENT_LIST_DIR}/src/netif/rpi-plc-sim.c
		${CMAKE_CURRENT_LIST_DIR}/src/netif/rpi-udp-broadcast.c
		${CMAKE_CURRENT_LIST_DIR}/src/storage/rpi-tl-hal.c
		${CMAKE_CURRENT_LIST_DIR}/src/storage/rpi-storage-hal.c
		${CMAKE_CURRENT_LIST_DIR}/src/storage/rpi-file-io.c
		${CMAKE_CURRENT_LIST_DIR}/src/crypto/rpi-soft-hsm-crypto-hal.c
		${CMAKE_CURRENT_LIST_DIR}/src/crypto/rpi-soft-hsm-keypair-hal.c
		${CMAKE_CURRENT_LIST_DIR}/src/rpi-global-hal.c
		${CMAKE_CURRENT_LIST_DIR}/src/threads/event-group-bits.c
		)

#
#   Include directories
#
target_include_directories(rpi-common
		PUBLIC
		${CMAKE_CURRENT_LIST_DIR}/include
		${CMAKE_CURRENT_LIST_DIR}/../ext/deps/include
		${CMAKE_CURRENT_LIST_DIR}/../ext/deps/include/virgil/crypto/common
		)

#
#	Link libraries
#
find_package (Threads)
target_link_libraries(rpi-common
		PUBLIC
		converters
		${CMAKE_CURRENT_LIST_DIR}/../ext/deps/lib/libvsc_foundation.a
		${CMAKE_CURRENT_LIST_DIR}/../ext/deps/lib/libvsc_common.a
		${CMAKE_CURRENT_LIST_DIR}/../ext/deps/lib/libmbedcrypto.a
		${CMAKE_CURRENT_LIST_DIR}/../ext/deps/lib/libed25519.a
		sdmp
		secbox
		trust_list
		${CMAKE_THREAD_LIBS_INIT}

		PRIVATE
		enable_pedantic_mode
		)
#
# Format code
#
if(COMMAND add_clangformat)
	add_clangformat(rpi-common)
endif()