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

#
#   Clang format
#
include("ap/security-sdk/cmake/clangformat.cmake")

#
#   Setup project
#
project(iot-rpi-gateway VERSION 0.1.0 LANGUAGES C)


#
#   Address sanitizer
#
set(USE_ASAN OFF CACHE BOOL "Enable Address sanitizer")
message("-- Address Sanitizer: ${USE_ASAN}")
if (USE_ASAN)
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
endif()


#
#   Undefined behavior sanitizer
#
set(USE_UBSAN OFF CACHE BOOL "Enable Undefined behavior sanitizer")
message("-- Undefined behavior Sanitizer: ${USE_UBSAN}")
if (USE_UBSAN)
    set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")
    set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")
endif()

#
#   Security processor
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/sp)


#
#   Application
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ap)

#
#   MCU Initializer
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/device/initializer)

# Build examples
if (ENABLE_EXAMPLES)
    add_subdirectory (examples/iot_crypto_app)
endif (ENABLE_EXAMPLES)

# Unit tests
#if (ENABLE_TESTING)
    enable_testing ()
    add_subdirectory (tests)
#endif (ENABLE_TESTING)
