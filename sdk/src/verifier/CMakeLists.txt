project(keystone-verifier C CXX)

set(CFLAGS      "-Wall ")
set(LDFLAGS     "-static")

set(SOURCE_FILES
    json11.cpp
    keys.cpp
    Report.cpp
    falcon512/codec.c
    falcon512/common.c
    falcon512/falcon.c
    falcon512/fft.c
    falcon512/fpr.c
    falcon512/keygen.c
    falcon512/rng.c
    falcon512/shake.c
    falcon512/sign.c
    falcon512/vrfy.c
    )

set(INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/include/verifier)

set(CMAKE_C_FLAGS          "${CMAKE_C_FLAGS} ${CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LDFLAGS}")

include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES} ${COMMON_SOURCE_FILES})

install(TARGETS ${PROJECT_NAME} DESTINATION ${out_dir}/lib)
install(DIRECTORY ${INCLUDE_DIRS} DESTINATION ${out_dir}/include)
