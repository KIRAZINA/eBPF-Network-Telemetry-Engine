# src/kernel/CMakeLists.txt — kernel-space eBPF bytecode build.
#
# Compiles every *.bpf.c with:
#   clang -target bpf -O2 -g -nostdinc -ffreestanding -fno-stack-protector ...
# into *.bpf.o. No standard library, no C++ flags, no -Werror leakage.
#
# Graceful degradation:
#   - Non-Linux host or missing Clang  -> informative STATUS, no targets.
#   - Missing vmlinux.h                -> compile with -DTELEMETRY_NO_VMLINUX_H
#                                        (BPF source uses minimal CO-RE stubs).
#   - Missing /sys/kernel/btf/vmlinux  -> runtime load guarded in daemon.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "src/kernel: skipping BPF build on non-Linux host (${CMAKE_SYSTEM_NAME}).")
    return()
endif()

if(NOT CLANG_EXECUTABLE)
    message(STATUS "src/kernel: clang not found; skipping BPF bytecode targets.")
    return()
endif()

# --- Clang builtin headers (needed with -nostdinc for __builtin_memcpy etc.) ---
execute_process(
    COMMAND "${CLANG_EXECUTABLE}" -print-file-name=include
    OUTPUT_VARIABLE CLANG_BUILTIN_INCLUDE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# --- Kernel UAPI headers for -nostdinc freestanding build ---
# Prefer /usr/include (linux/, asm/) directly; fall back gracefully.
set(BPF_CFLAGS
    -target bpf
    -O2
    -g
    -nostdinc
    -ffreestanding
    -fno-stack-protector
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fno-jump-tables
    -Wall
    -Wextra
)

set(BPF_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/include"
    /usr/include
    /usr/include/x86_64-linux-gnu
)
if(CLANG_BUILTIN_INCLUDE AND EXISTS "${CLANG_BUILTIN_INCLUDE}")
    list(APPEND BPF_INCLUDE_DIRS "${CLANG_BUILTIN_INCLUDE}")
endif()

# NOTE: -I and its directory stay SEPARATE list items. A combined "-I<dir>"
# item makes the Makefile generator embed literal quote characters around
# directories containing spaces, which clang then treats as part of the path
# (observed: "-I\"/mnt/...\""). Separate items pass through cleanly.
set(BPF_INCLUDES "")
foreach(_incdir IN LISTS BPF_INCLUDE_DIRS)
    list(APPEND BPF_INCLUDES -I "${_incdir}")
endforeach()
unset(_incdir)

# CO-RE: prefer real vmlinux.h, else stub fallback inside telemetry.bpf.c.
# NOTE (fresh-build ordering): the header may not exist at configure time yet
# be generated before compilation (TARGET generate-vmlinux-header, defined in
# the root CMakeLists when bpftool + host BTF are present). In that case the
# HAVE path is still correct — the file-level DEPENDS below orders generation
# strictly before each .bpf.o compile. Only when generation is unavailable AND
# no header exists do we take the stub path (vmlinux_compat.h is self-sufficient).
if(EXISTS "${PROJECT_SOURCE_DIR}/include/vmlinux.h" OR TARGET generate-vmlinux-header)
    set(BPF_VMLINUX_DEFINE "-DHAVE_VMLINUX_H=1")
    set(BPF_VMLINUX_DEPENDS "${PROJECT_SOURCE_DIR}/include/vmlinux.h")
else()
    set(BPF_VMLINUX_DEFINE "-DTELEMETRY_NO_VMLINUX_H=1")
    set(BPF_VMLINUX_DEPENDS "")
    message(STATUS "src/kernel: include/vmlinux.h absent and not generatable; BPF objects use stub types. "
                   "Generate with: bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h")
endif()

file(GLOB BPF_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.bpf.c")
if(NOT BPF_SOURCES)
    message(WARNING "src/kernel: no *.bpf.c sources found.")
    return()
endif()

set(BPF_OBJECTS "")
foreach(bpf_src IN LISTS BPF_SOURCES)
    get_filename_component(bpf_name "${bpf_src}" NAME_WE)  # e.g. telemetry.bpf
    string(REPLACE ".bpf" "" bpf_stem "${bpf_name}")
    set(bpf_obj "${CMAKE_CURRENT_BINARY_DIR}/${bpf_stem}.bpf.o")

    add_custom_command(
        OUTPUT "${bpf_obj}"
        COMMAND "${CLANG_EXECUTABLE}"
                ${BPF_CFLAGS}
                ${BPF_INCLUDES}
                "${BPF_VMLINUX_DEFINE}"
                -D__TARGET_ARCH_x86
                -c "${bpf_src}"
                -o "${bpf_obj}"
        DEPENDS "${bpf_src}"
                "${PROJECT_SOURCE_DIR}/include/event_types.h"
                "${CMAKE_CURRENT_SOURCE_DIR}/vmlinux_compat.h"
                ${BPF_VMLINUX_DEPENDS}
        COMMENT "Compiling BPF ${bpf_name}.c -> ${bpf_stem}.bpf.o"
        VERBATIM
    )
    list(APPEND BPF_OBJECTS "${bpf_obj}")
endforeach()

# If the root generate-vmlinux-header target exists, order BPF objects after it.
if(TARGET generate-vmlinux-header)
    # Attach dependency via a wrapper target (objects themselves can't DEPENDS on target).
    add_custom_target(ebpf-vmlinux-dep DEPENDS generate-vmlinux-header)
    add_custom_target(ebpf_kernel_objects ALL DEPENDS ${BPF_OBJECTS} ebpf-vmlinux-dep)
else()
    add_custom_target(ebpf_kernel_objects ALL DEPENDS ${BPF_OBJECTS})
endif()

# Back-compat alias requested in roadmap docs.
add_custom_target(ebpf DEPENDS ebpf_kernel_objects)

install(FILES ${BPF_OBJECTS}
    DESTINATION "${CMAKE_INSTALL_DATADIR}/ebpf-telemetry/bpf"
    OPTIONAL
)
