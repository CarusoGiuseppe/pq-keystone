set(eapp_bin attestor)
set(eapp_src eapp/attestor.c)
set(host_bin attestor-runner)
set(host_src host/attestor-runner.cpp host/host.cpp host/verifier.cpp)
set(package_name "attestor.ke")
set(eyrie_plugins "none")


if(NOT DEFINED fw_bin)
   set(fw_bin ../../../images/fw_jump.bin)
endif()
get_filename_component(fw_file ${fw_bin} NAME)
set(package_script "./attestor-runner attestor eyrie-rt loader.bin --sm-bin ${fw_file}")

# eapp

add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} "-nostdlib -static" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})
target_include_directories(${eapp_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin}
  ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER})
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
  )
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/common
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PUBLIC ${KEYSTONE_SDK_DIR}/include/verifier)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add sm binary -- TODO: fix, should come from upper levels
if(NOT DEFINED fw_bin)
  message(AUTHOR_WARNING "fw_bin should be defined by upper CMake files/ build system. Setting to default")
  set(fw_bin ../../../images/fw_payload.bin)
endif()

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin} ${fw_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
