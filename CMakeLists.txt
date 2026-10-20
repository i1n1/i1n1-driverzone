# SPDX-License-Identifier: GPL-2.0-only
#
# Build-only top level for the i1n1-driverzone repository.
cmake_minimum_required(VERSION 3.22)

# Same deployment target as the other i1n1 repositories so C objects agree.
if(CMAKE_HOST_APPLE AND NOT CMAKE_OSX_DEPLOYMENT_TARGET)
  set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS deployment target")
endif()

project(i1n1-driverzone VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set_property(GLOBAL PROPERTY I1N1_REPO_DRIVERZONE_LOADED TRUE)
set(I1N1_DRIVERZONE_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE INTERNAL "")

include("${CMAKE_CURRENT_LIST_DIR}/cmake/i1n1_deps.cmake")

i1n1_require(core)
i1n1_require(platform)

add_subdirectory(src/driverzone)
