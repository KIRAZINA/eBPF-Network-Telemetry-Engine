# src/daemon/CMakeLists.txt — user-space C++20 daemon.
#
# Strict production flags come from cmake/CompilerFlags.cmake
# (-O3 -Wall -Wextra -Werror -pedantic -Wshadow -Wnon-virtual-dtor ...).
# All linkage is target-scoped (target_include_directories / target_link_libraries).

set(DAEMON_TARGET ebpf-telemetry-daemon)

set(DAEMON_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/bpf_manager.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/ring_buffer_consumer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/connection_tracker.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/anomaly_detector.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/metrics_exporter.cpp"
)

add_executable("${DAEMON_TARGET}" ${DAEMON_SOURCES})

target_include_directories("${DAEMON_TARGET}" PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/include"
)

target_compile_features("${DAEMON_TARGET}" PRIVATE cxx_std_20)
telemetry_apply_strict_warnings("${DAEMON_TARGET}")
telemetry_apply_sanitizers("${DAEMON_TARGET}")

target_link_libraries("${DAEMON_TARGET}" PRIVATE Threads::Threads)

if(TARGET ZLIB::ZLIB)
    target_link_libraries("${DAEMON_TARGET}" PRIVATE ZLIB::ZLIB)
endif()

if(TARGET Libbpf::libbpf)
    target_link_libraries("${DAEMON_TARGET}" PRIVATE Libbpf::libbpf)
    target_compile_definitions("${DAEMON_TARGET}" PRIVATE HAVE_LIBBPF=1)
else()
    # Portable stub mode (e.g. Windows/macOS configure): daemon builds and
    # runs its pipeline self-test without loading kernel objects.
    target_compile_definitions("${DAEMON_TARGET}" PRIVATE TELEMETRY_NO_LIBBPF=1)
    message(STATUS "src/daemon: building without libbpf (stub mode).")
endif()

if(TARGET Elf::elf AND NOT TARGET Libbpf::libbpf)
    target_link_libraries("${DAEMON_TARGET}" PRIVATE Elf::elf)
endif()

set_target_properties("${DAEMON_TARGET}" PROPERTIES
    OUTPUT_NAME "ebpf-telemetry-daemon"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

install(TARGETS "${DAEMON_TARGET}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
