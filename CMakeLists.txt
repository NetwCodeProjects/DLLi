cmake_minimum_required(VERSION 3.15)
project(DLLInjector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure UNICODE/WIDE API support
add_definitions(-DUNICODE -D_UNICODE)

# Add executable
add_executable(DLLInjector
    main.cpp
    http.cpp
    crypto.cpp
    etw.cpp
    ntdll.cpp
    remote.cpp
    injector.cpp
    loader.cpp
    embedded.cpp  # ← only include if you're embedding the DLL
)

# Link required libraries
target_link_libraries(DLLInjector
    wininet
    advapi32
)
