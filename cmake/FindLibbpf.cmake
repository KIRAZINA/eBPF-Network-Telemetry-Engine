# FindLibbpf.cmake — Find module for libbpf (https://github.com/libbpf/libbpf)
#
# Imported target: Libbpf::libbpf
# Result variables:
#   Libbpf_FOUND, Libbpf_INCLUDE_DIRS, Libbpf_LIBRARIES, Libbpf_VERSION
#
# Search order: pkg-config -> standard paths -> user hints
# Hints: Libbpf_ROOT, LIBBPF_ROOT, CMAKE_PREFIX_PATH, PKG_CONFIG_USE_CMAKE_PREFIX_PATH.

include(FindPackageHandleStandardArgs)

# Allow <PackageName>_ROOT (CMake >= 3.12 policy CMP0074).
if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_LIBBPF QUIET libbpf)
    if(PC_LIBBPF_FOUND)
        set(Libbpf_VERSION "${PC_LIBBPF_VERSION}")
    endif()
endif()

find_path(Libbpf_INCLUDE_DIR
    NAMES bpf/bpf.h bpf/libbpf.h
    HINTS
        ${Libbpf_ROOT}/include
        ${LIBBPF_ROOT}/include
        ${PC_LIBBPF_INCLUDEDIR}
        ${PC_LIBBPF_INCLUDE_DIRS}
    PATH_SUFFIXES include
    DOC "libbpf include directory"
)

find_library(Libbpf_LIBRARY
    NAMES bpf
    HINTS
        ${Libbpf_ROOT}/lib
        ${Libbpf_ROOT}/lib64
        ${LIBBPF_ROOT}/lib
        ${LIBBPF_ROOT}/lib64
        ${PC_LIBBPF_LIBDIR}
        ${PC_LIBBPF_LIBRARY_DIRS}
    DOC "libbpf library"
)

# Fallback version scrape from bpf/libbpf_version.h when pkg-config is absent.
if(Libbpf_INCLUDE_DIR AND NOT Libbpf_VERSION)
    file(STRINGS "${Libbpf_INCLUDE_DIR}/bpf/libbpf_version.h" _ver_major REGEX "#define[ \t]+LIBBPF_MAJOR_VERSION[ \t]+[0-9]+")
    file(STRINGS "${Libbpf_INCLUDE_DIR}/bpf/libbpf_version.h" _ver_minor REGEX "#define[ \t]+LIBBPF_MINOR_VERSION[ \t]+[0-9]+")
    string(REGEX MATCH "[0-9]+" Libbpf_VERSION_MAJOR "${_ver_major}")
    string(REGEX MATCH "[0-9]+" Libbpf_VERSION_MINOR "${_ver_minor}")
    if(Libbpf_VERSION_MAJOR)
        set(Libbpf_VERSION "${Libbpf_VERSION_MAJOR}.${Libbpf_VERSION_MINOR}")
    endif()
    unset(_ver_major)
    unset(_ver_minor)
endif()

find_package_handle_standard_args(Libbpf
    REQUIRED_VARS Libbpf_LIBRARY Libbpf_INCLUDE_DIR
    VERSION_VAR Libbpf_VERSION
)

if(Libbpf_FOUND)
    set(Libbpf_INCLUDE_DIRS "${Libbpf_INCLUDE_DIR}")
    set(Libbpf_LIBRARIES "${Libbpf_LIBRARY}")
    mark_as_advanced(Libbpf_INCLUDE_DIR Libbpf_LIBRARY)

    if(NOT TARGET Libbpf::libbpf)
        add_library(Libbpf::libbpf UNKNOWN IMPORTED)
        set_target_properties(Libbpf::libbpf PROPERTIES
            IMPORTED_LOCATION "${Libbpf_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${Libbpf_INCLUDE_DIR}"
        )
        # libbpf consumers almost always need elf + zlib transitively.
        if(TARGET Elf::elf)
            set_property(TARGET Libbpf::libbpf APPEND PROPERTY INTERFACE_LINK_LIBRARIES Elf::elf)
        endif()
        if(TARGET ZLIB::ZLIB)
            set_property(TARGET Libbpf::libbpf APPEND PROPERTY INTERFACE_LINK_LIBRARIES ZLIB::ZLIB)
        endif()
    endif()
    message(STATUS "Found Libbpf ${Libbpf_VERSION}: ${Libbpf_LIBRARY}")
endif()
