cmake_minimum_required (VERSION 2.6)
project (light_pcapng C)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/include/ -Wall -O2 -fPIC -DUNIVERSAL -g")

add_library (light_pcapng SHARED
    src/light_io.c
    src/light_pcapng.c
    src/light_pcapng_cont.c
    src/light_platform.c
    src/light_manipulate.c
    src/light_internal.c
    src/light_alloc.c
    )

add_library (light_pcapng_static STATIC
    src/light_io.c
    src/light_pcapng.c
    src/light_pcapng_cont.c
    src/light_platform.c
    src/light_manipulate.c
    src/light_internal.c
    src/light_alloc.c
    )