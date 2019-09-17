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
#   Settings
#
option(GO_DISABLE "Disable Go apps" OFF)
option(BIGENDIAN_64_BIT_BUILD "Build for MIPS 64 big endian" OFF)
option(BIGENDIAN_32_BIT_BUILD "Build for MIPS 32 big endian" OFF)
option(GATEWAY_SIMULATOR "On/Off code for simulator." ON)
option(VIRGIL_IOT_MCU_BUILD "Enable build for MCU" OFF)

# Sanitizers
option(USE_ASAN "On/Off Address sanitizer." OFF)
option(USE_MSAN "On/Off Memory sanitizer." OFF)
option(USE_LSAN "On/Off Leak memory sanitizer." OFF)
option(USE_UBSAN "On/Off Undefined behavior sanitizer." OFF)
option(USE_TSAN "On/Off Thread sanitizer." OFF)

#
#   Check setting compatibility
#
if (BIGENDIAN_64_BIT_BUILD)
    set(GO_DISABLE ON CACHE BOOL "Disable Go apps" FORCE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/mips64.toolchain.cmake")
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/ext/deps/mips64")
endif ()

if (BIGENDIAN_32_BIT_BUILD)
    set(GO_DISABLE ON CACHE BOOL "Disable Go apps" FORCE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/mips32.toolchain.cmake")
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/ext/deps/mips32")
endif ()

if (NOT BIGENDIAN_64_BIT_BUILD AND NOT BIGENDIAN_32_BIT_BUILD)
    set(CRYPTO_C_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}/ext/deps/host")
endif()

#
#   Include CMake Helpers
#
include(cmake/helpers.cmake)

#
#   Golang
#
if (NOT GO_DISABLE)
    include(cmake/golang.cmake)
    include(cmake/flags.cmake)
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
endif ()

#
#   Clang format
#
include(${CMAKE_CURRENT_LIST_DIR}/ext/virgil-iot-sdk/cmake/clangformat.cmake)

#
#   Setup project
#
if (GO_DISABLE)
    project(iot-rpi VERSION 0.1.0 LANGUAGES C)
else ()
    project(iot-rpi VERSION 0.1.0 LANGUAGES C Go)
endif ()

#
#   Address sanitizer
#
message("-- Address Sanitizer: ${USE_ASAN}")
if (USE_ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
endif ()

if (UNIX AND NOT APPLE)
    #
    #   Memory sanitizer
    #
    message("-- Memory Sanitizer: ${USE_MSAN}")
    if (USE_MSAN)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=memory")
        set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=memory")
    endif ()

    #
    #   Leak sanitizer
    #
    message("-- Leak memory Sanitizer: ${USE_LSAN}")
    if (USE_LSAN)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=leak")
        set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=leak")
    endif ()
endif ()

#
#   Undefined behavior sanitizer
#
message("-- Undefined behavior Sanitizer: ${USE_UBSAN}")
if (USE_UBSAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=undefined")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")
endif ()

#
#   Thread sanitizer
#
message("-- Thread Sanitizer: ${USE_TSAN}")
if (USE_TSAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=thread")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=thread")
endif ()

if (USE_ASAN OR USE_MSAN OR USE_LSAN OR USE_UBSAN OR USE_TSAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -g")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -g")
endif ()

# ---------------------------------------------------------------------------
#   Folders with targets
# ---------------------------------------------------------------------------

#
#   Virgil IoT SDK
#
set(VIRGIL_IOT_MCU_BUILD OFF CACHE BOOL "Turn off MCU build" FORCE)
set(VIRGIL_IOT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ext/virgil-iot-sdk CACHE STRING "Path to the Virgil IoT SDK")
set(VIRGIL_IOT_CONFIG_DIRECTORY ${VIRGIL_IOT_DIRECTORY}/config/rpi CACHE STRING "Path to the Virgil IoT SDK configuration")
add_subdirectory(${VIRGIL_IOT_DIRECTORY})

#
#   aws-sdk
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ext/aws-sdk)

#
#   Common code library
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/common)

#
#   Initalizers for Gateway and Thing
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/initializer)

#
#   Gateway application
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/gateway)

#
#   Thing application
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/thing)

#
#   Unit tests
#
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
