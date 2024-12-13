cmake_minimum_required(VERSION 3.8)

project(libashmem VERSION 1.0.0 LANGUAGES C CXX)

include(CTest)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(BUILD_EXAMPLES "Build examples using library" ON)
option(ENABLE_TESTS "Build examples using library" OFF)

add_compile_options(-Wall -Wextra -Wpedantic)
set(SRCS ashmem.cpp)
if(BUILD_SHARED_LIBS)
	add_library(ashmem SHARED ${SRCS})
else()
	add_library(ashmem STATIC ${SRCS})
endif()
set_property(TARGET ashmem PROPERTY C_STANDARD 11)
set_property(TARGET ashmem PROPERTY CXX_STANDARD 17)

include_directories(include)
target_compile_options(ashmem PRIVATE -fno-threadsafe-statics)
target_link_options(ashmem PUBLIC -Wl,--wrap=mmap)
target_link_libraries(ashmem android)
set_target_properties(ashmem PROPERTIES LINKER_LANGUAGE CXX)



if(ENABLE_TESTS)
enable_testing()
find_package(GTest REQUIRED)
include(GoogleTest)
add_executable(ashmem_test "ashmem_test.cpp")

target_link_libraries(ashmem_test ashmem GTest::gtest GTest::gtest_main)

gtest_discover_tests(ashmem_test)
endif()

if(BUILD_EXAMPLES)
add_executable(shm-launch ${PROJECT_SOURCE_DIR}/examples/shm-launch.c)
target_link_libraries(shm-launch PRIVATE ashmem)
add_executable(test-client ${PROJECT_SOURCE_DIR}/examples/test-client.c)
target_link_libraries(test-client PRIVATE ashmem)
add_executable(test-server ${PROJECT_SOURCE_DIR}/examples/test-server.c)
target_link_libraries(test-server PRIVATE ashmem)
endif()

install(FILES ${PROJECT_SOURCE_DIR}/include/ashm.h DESTINATION include)
install(
      TARGETS ashmem
	  EXPORT ashmem-targets
      RUNTIME
        DESTINATION bin
      LIBRARY
        DESTINATION lib
      ARCHIVE
        DESTINATION lib
      INCLUDES
        DESTINATION include
    )

install(EXPORT ashmem-targets
    FILE ashmem.cmake
    DESTINATION lib/cmake/ashmem
)