# SPDX-License-Identifier: GPL-2.0-only

add_library(i1n1_driverzone STATIC
  rpc_shim.c
  vmx_backend.c
  vmx/vmx_caps.c
  vmx/vmx_fields.c
  vmx/vmx_ept_build.c
  vmx/vmx_exit.c
  vmx/vmx_session.c
  vmx/vmx_insn_x86.c
  softvm/nvme_sim.c
  softvm/xhci_sim.c)
add_library(i1n1::driverzone ALIAS i1n1_driverzone)

target_include_directories(i1n1_driverzone PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vmx>)
target_link_libraries(i1n1_driverzone PUBLIC i1n1_bridge i1n1_ept i1n1_mmio)
target_compile_features(i1n1_driverzone PUBLIC c_std_11)
i1n1_apply_project_defaults(i1n1_driverzone)
