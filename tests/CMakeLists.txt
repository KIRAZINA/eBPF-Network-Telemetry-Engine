# tests/CMakeLists.txt — Catch2 unit-test suite (FetchContent + CTest).
#
# Layout: add_executable(telemetry_tests ...) with target-scoped includes/links.
# Catch2 v3 is fetched at configure time; on offline hosts set
# FETCHCONTENT_FULLY_DISCONNECTED=ON with a pre-populated _deps cache.

include(FetchContent)

set(CATCH2_TAG "v3.5.4" CACHE STRING "Catch2 release tag for FetchContent")

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG "${CATCH2_TAG}"
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(Catch2)

list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)

set(TEST_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/test_event_layout.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_sliding_window.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_ring_dispatch.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_connection_tracker.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_anomaly_detector.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_metrics_exporter.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_pipeline_integration.cpp"
)

# Engine sources under test (header-only sliding_window needs no TU).
set(ENGINE_SOURCES
    "${PROJECT_SOURCE_DIR}/src/daemon/connection_tracker.cpp"
    "${PROJECT_SOURCE_DIR}/src/daemon/anomaly_detector.cpp"
    "${PROJECT_SOURCE_DIR}/src/daemon/ring_buffer_consumer.cpp"
    "${PROJECT_SOURCE_DIR}/src/daemon/metrics_exporter.cpp"
)

add_executable(telemetry_tests ${TEST_SOURCES} ${ENGINE_SOURCES})

target_include_directories(telemetry_tests PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/src/daemon"
)

target_link_libraries(telemetry_tests PRIVATE
    Catch2::Catch2WithMain
    Threads::Threads
)

target_compile_features(telemetry_tests PRIVATE cxx_std_20)
telemetry_apply_strict_warnings(telemetry_tests)
telemetry_apply_sanitizers(telemetry_tests)

# Relax warnings that fire inside Catch2's own headers when its assertion
# macros are expanded in our TUs (sign-conversion on comparisons,
# non-virtual-dtor on Catch::ITransientExpression); keep -Werror for our code.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(telemetry_tests PRIVATE
        -Wno-sign-conversion -Wno-conversion -Wno-non-virtual-dtor)
endif()

set_target_properties(telemetry_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

catch_discover_tests(telemetry_tests)
