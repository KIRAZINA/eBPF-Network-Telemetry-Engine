# CompilerFlags.cmake — strict, production-grade warning set for user-space C++20.
#
# Usage (in any user-space target):
#   include(CompilerFlags)
#   telemetry_apply_strict_warnings(<target> [CXX_ONLY])
#   telemetry_apply_sanitizers(<target>)   # Debug + ENABLE_ASAN only
#
# BPF kernel flags are intentionally NOT defined here (see src/kernel/CMakeLists.txt).

# Base warning sets per compiler.
set(TELEMETRY_GCC_CLANG_WARNINGS
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wunused
    -Woverloaded-virtual
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-fallthrough
)

set(TELEMETRY_MSVC_WARNINGS
    /W4
    /w14242  # possible loss of data (conversion)
    /w14254  # conversion: possible loss of data (smaller type)
    /w14263  # member function does not override (virtual)
    /w14265  # class has virtual functions but destructor is not virtual
    /w14287  # unsigned/negative constant mismatch
    /we4289  # loop variable shadowing (as error)
    /w14296  # expression is always false
    /w14311  # pointer truncation
    /w14545  # expression before comma has no effect
    /w14546  # function call before comma missing argument list
    /w14619  # pragma warning: no warning number
    /w14640  # thread un-safe static member init
    /w14826  # conversion from 'type1' to 'type2' is sign-extended
    /w14905  # wide string literal cast to LPSTR
    /w14906  # string literal cast to LPWSTR
    /w14928  # illegal copy-initialization
)

function(telemetry_apply_strict_warnings target)
    if(NOT TARGET "${target}")
        message(FATAL_ERROR "telemetry_apply_strict_warnings: '${target}' is not a CMake target")
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        target_compile_options("${target}" PRIVATE ${TELEMETRY_GCC_CLANG_WARNINGS})
        if(ENABLE_WERROR)
            target_compile_options("${target}" PRIVATE -Werror)
        endif()
        # Position-independent code + hidden visibility are sane daemon defaults.
        set_target_properties("${target}" PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN ON
        )
    elseif(MSVC)
        target_compile_options("${target}" PRIVATE ${TELEMETRY_MSVC_WARNINGS})
        if(ENABLE_WERROR)
            target_compile_options("${target}" PRIVATE /WX)
        endif()
        # MSVC: standards-conformance + UTF-8 sources.
        target_compile_options("${target}" PRIVATE /permissive- /Zc:__cplusplus /utf-8)
    endif()

    # Require C++20 at target level even if global CMAKE_CXX_STANDARD drifts.
    target_compile_features("${target}" PRIVATE cxx_std_20)
endfunction()

# AddressSanitizer + UBSan for Debug builds when -DENABLE_ASAN=ON.
function(telemetry_apply_sanitizers target)
    if(NOT ENABLE_ASAN)
        return()
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        message(WARNING "ENABLE_ASAN requested but unsupported for ${CMAKE_CXX_COMPILER_ID}; skipping.")
        return()
    endif()
    target_compile_options("${target}" PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined;-fno-omit-frame-pointer>)
    target_link_options("${target}" PRIVATE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>)
endfunction()

# Production Release defaults: -O3 is the compiler default at -DCMAKE_BUILD_TYPE=Release
# for single-config generators. For multi-config / exotic toolchains, enforce explicitly.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        add_compile_options(-O3)
    endif()
endif()
