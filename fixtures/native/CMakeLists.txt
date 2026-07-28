cmake_minimum_required(VERSION 3.20)
project(headless_re_fixtures LANGUAGES C)

add_executable(console_fixture console_fixture.c)
add_executable(headless_fixture WIN32 console_fixture.c)
add_executable(gui_fixture WIN32 gui_fixture.c)
add_executable(predictable_imports_fixture predictable_imports_fixture.c)
add_library(event_fixture SHARED event_fixture.c)
add_library(runtime_decrypt_fixture SHARED runtime_decrypt_fixture.c)

set_target_properties(
    console_fixture
    headless_fixture
    gui_fixture
    predictable_imports_fixture
    event_fixture
    runtime_decrypt_fixture
    PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}"
)

set_target_properties(event_fixture runtime_decrypt_fixture PROPERTIES PREFIX "")
target_compile_definitions(
    headless_fixture
    PRIVATE HEADLESS_RE_FIXTURE_WINDOWS_SUBSYSTEM
)
target_compile_definitions(gui_fixture PRIVATE UNICODE _UNICODE)
