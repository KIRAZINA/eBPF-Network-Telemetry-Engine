cmake_minimum_required(VERSION 3.22)

project(ebpf-telemetry
    VERSION 0.1.0
    DESCRIPTION "eBPF Network Telemetry & Security Engine (kernel-space XDP/tracepoint + C++20 user-space daemon)"
    HOMEPAGE_URL "https://example.com/ebpf-telemetry"
    LANGUAGES C CXX
)

# ---------------------------------------------------------------------------
# Global language standards & layout
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Modern CMake module path (custom Find modules live in cmake/)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CTest)

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------
option(BUILD_TESTING "Build unit test suite (Catch2)" ON)
option(ENABLE_WERROR "Treat warnings as errors in user-space code" ON)
option(ENABLE_ASAN "Enable AddressSanitizer + UBSan for Debug user-space builds" OFF)
option(GENERATE_VMLINUX_H "Auto-generate include/vmlinux.h from host BTF at build time" ON)
option(WITH_LIBBPF "Require libbpf for the user-space daemon (required on Linux)" ON)

# ---------------------------------------------------------------------------
# Strict compiler flags (user-space). BPF flags live in src/kernel/CMakeLists.txt
# ---------------------------------------------------------------------------
include(CompilerFlags)

# ---------------------------------------------------------------------------
# Toolchain sanity checks
# ---------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13.0")
        message(WARNING "GCC ${CMAKE_CXX_COMPILER_VERSION} detected; GCC 13+ is required for full C++20 support.")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "16.0")
        message(WARNING "Clang ${CMAKE_CXX_COMPILER_VERSION} detected; Clang 16+ is recommended for C++20.")
    endif()
elseif(MSVC)
    message(WARNING "MSVC detected. eBPF kernel targets require Linux + Clang; only user-space/tests are portable.")
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Non-Linux host (${CMAKE_SYSTEM_NAME}) detected: eBPF kernel compilation and BTF generation will be skipped/guarded.")
endif()

# eBPF/BPF skeleton generation needs clang with bpf target (checked in src/kernel).
find_program(CLANG_EXECUTABLE NAMES clang clang-18 clang-17 clang-16 clang-15)
if(CLANG_EXECUTABLE)
    message(STATUS "Found Clang for BPF target: ${CLANG_EXECUTABLE}")
else()
    message(STATUS "Clang not found: kernel-space BPF objects will be unavailable (user-space still builds).")
endif()

# ---------------------------------------------------------------------------
# vmlinux.h generation from host BTF
#   Spec: bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
# ---------------------------------------------------------------------------
find_program(BPFTOOL_EXECUTABLE NAMES bpftool)

# The /usr/sbin/bpftool wrapper on some distros refuses to run when the
# running kernel has no matching linux-tools package (e.g. WSL2 kernels).
# Validate the candidate up front; otherwise hunt for a versioned real binary
# (BTF dump reads a file and needs no kernel-version match). If nothing runs,
# generation stays disabled and the stub fallback in src/kernel applies.
if(BPFTOOL_EXECUTABLE)
    execute_process(COMMAND "${BPFTOOL_EXECUTABLE}" version
        RESULT_VARIABLE _bpftool_rc
        OUTPUT_QUIET ERROR_QUIET)
    if(NOT _bpftool_rc EQUAL 0)
        set(BPFTOOL_EXECUTABLE "")
    endif()
    unset(_bpftool_rc)
endif()
if(NOT BPFTOOL_EXECUTABLE AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(GLOB _bpftool_candidates "/usr/lib/linux-tools/*/bpftool")
    foreach(_cand IN LISTS _bpftool_candidates)
        execute_process(COMMAND "${_cand}" version
            RESULT_VARIABLE _cand_rc
            OUTPUT_QUIET ERROR_QUIET)
        if(_cand_rc EQUAL 0)
            set(BPFTOOL_EXECUTABLE "${_cand}")
            break()
        endif()
    endforeach()
    unset(_bpftool_candidates)
    unset(_cand)
    unset(_cand_rc)
endif()
if(BPFTOOL_EXECUTABLE)
    message(STATUS "Using bpftool: ${BPFTOOL_EXECUTABLE}")
endif()

set(VMLINUX_BTF_FILE "/sys/kernel/btf/vmlinux" CACHE FILEPATH "Path to host kernel BTF file")
set(VMLINUX_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/vmlinux.h")

if(GENERATE_VMLINUX_H AND BPFTOOL_EXECUTABLE AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(EXISTS "${VMLINUX_BTF_FILE}")
        # NOTE: shell redirection (>) needs an explicit shell invocation.
        add_custom_command(
            OUTPUT "${VMLINUX_HEADER}"
            COMMAND /bin/sh -c "\"${BPFTOOL_EXECUTABLE}\" btf dump file \"${VMLINUX_BTF_FILE}\" format c > \"${VMLINUX_HEADER}\""
            COMMENT "Generating vmlinux.h from ${VMLINUX_BTF_FILE} via bpftool"
            VERBATIM
        )
        add_custom_target(generate-vmlinux-header
            DEPENDS "${VMLINUX_HEADER}"
            COMMENT "vmlinux.h generation target"
        )
        message(STATUS "vmlinux.h will be generated from ${VMLINUX_BTF_FILE}")
    else()
        message(WARNING
            "BTF file ${VMLINUX_BTF_FILE} not found; skipping vmlinux.h auto-generation. "
            "Kernel CO-RE build needs either ${VMLINUX_HEADER} checked in or a BTF-enabled host. "
            "See: https://docs.kernel.org/bpf/btf.html")
    endif()
else()
    if(GENERATE_VMLINUX_H AND NOT BPFTOOL_EXECUTABLE)
        message(STATUS "bpftool not found; vmlinux.h auto-generation disabled (provide include/vmlinux.h manually).")
    endif()
endif()

if(EXISTS "${VMLINUX_HEADER}")
    message(STATUS "Using vmlinux.h: ${VMLINUX_HEADER}")
else()
    message(STATUS "No vmlinux.h present; kernel sources fall back to minimal CO-RE stub types (see src/kernel).")
endif()

# ---------------------------------------------------------------------------
# Dependencies (user-space)
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)

# zlib (libbpf dependency + daemon compression hooks)
find_package(ZLIB)
if(NOT ZLIB_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WITH_LIBBPF)
    message(WARNING "ZLIB not found; libbpf feature set may be reduced.")
endif()

# libelf (libbpf dependency). No stock FindLibElf in CMake < 3.28, so probe manually.
find_path(LIBELF_INCLUDE_DIR NAMES libelf.h elf.h PATH_SUFFIXES libelf)
find_library(LIBELF_LIBRARY NAMES elf)
if(LIBELF_INCLUDE_DIR AND LIBELF_LIBRARY)
    set(LIBELF_FOUND TRUE)
    add_library(Elf::elf UNKNOWN IMPORTED)
    set_target_properties(Elf::elf PROPERTIES
        IMPORTED_LOCATION "${LIBELF_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBELF_INCLUDE_DIR}"
    )
    message(STATUS "Found libelf: ${LIBELF_LIBRARY}")
else()
    set(LIBELF_FOUND FALSE)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WITH_LIBBPF)
        message(WARNING "libelf not found; install libelf-dev/elfutils-libelf-devel for full libbpf support.")
    endif()
endif()

# libbpf — required on Linux, optional elsewhere (allows Windows/macOS configure).
find_package(Libbpf)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND WITH_LIBBPF AND NOT Libbpf_FOUND)
    message(WARNING
        "libbpf not found. On Debian/Ubuntu: sudo apt install libbpf-dev. "
        "Continuing configure; daemon links libbpf only when available. "
        "Set -DWITH_LIBBPF=OFF to silence.")
endif()

# ---------------------------------------------------------------------------
# Sub-directories — clean kernel/user-space separation
# ---------------------------------------------------------------------------
add_subdirectory(src/kernel)
add_subdirectory(src/daemon)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Convenience meta-target + install hints
# ---------------------------------------------------------------------------
# `cmake --build build --target ebpf` builds kernel BPF objects (if available).
# `cmake --build build --target daemon` builds user-space only.

message(STATUS "Configured ${PROJECT_NAME} ${PROJECT_VERSION} | BUILD_TYPE=${CMAKE_BUILD_TYPE} | CXX=${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
