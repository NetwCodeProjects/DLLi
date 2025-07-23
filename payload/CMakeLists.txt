cmake_minimum_required(VERSION 3.15)
project(PayloadDLL LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Build payload.dll as shared library
add_library(payload SHARED payload.cpp)

# Set output name to avoid "libpayload.dll"
set_target_properties(payload PROPERTIES
    OUTPUT_NAME "payload"
    SUFFIX ".dll"
    LINK_FLAGS "/SUBSYSTEM:WINDOWS"  # Hide console window
)
