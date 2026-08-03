cmake_minimum_required(VERSION 3.16)

project(cidr_toolkit VERSION 1.0.0 LANGUAGES CXX)

add_library(cidr_toolkit_lib src/ipv4_network.cpp)
target_include_directories(cidr_toolkit_lib PUBLIC include)
target_compile_features(cidr_toolkit_lib PUBLIC cxx_std_17)
set_target_properties(cidr_toolkit_lib PROPERTIES CXX_EXTENSIONS OFF)

add_executable(cidr-toolkit src/main.cpp)
target_link_libraries(cidr-toolkit PRIVATE cidr_toolkit_lib)

if(MSVC)
    set(CIDR_TOOLKIT_WARNINGS /W4 /permissive-)
else()
    set(CIDR_TOOLKIT_WARNINGS -Wall -Wextra -Wpedantic)
endif()

target_compile_options(cidr_toolkit_lib PRIVATE ${CIDR_TOOLKIT_WARNINGS})
target_compile_options(cidr-toolkit PRIVATE ${CIDR_TOOLKIT_WARNINGS})

include(CTest)

if(BUILD_TESTING)
    add_executable(cidr-toolkit-tests tests/test_ipv4_network.cpp)
    target_link_libraries(cidr-toolkit-tests PRIVATE cidr_toolkit_lib)

    target_compile_options(cidr-toolkit-tests PRIVATE ${CIDR_TOOLKIT_WARNINGS})
    add_test(NAME ipv4-network-tests COMMAND cidr-toolkit-tests)
endif()
