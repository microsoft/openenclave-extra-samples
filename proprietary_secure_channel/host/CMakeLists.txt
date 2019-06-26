# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT proprietarysecurechannel_u.h proprietarysecurechannel_u.c proprietarysecurechannel_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/proprietarysecurechannel.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/proprietarysecurechannel.edl)

add_executable(proprietary_secure_channel_host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/proprietarysecurechannel_u.c)

target_include_directories(proprietary_secure_channel_host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(proprietary_secure_channel_host openenclave::oehostapp)
