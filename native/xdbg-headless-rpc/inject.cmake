get_property(headless_re_rpc_injection_scheduled GLOBAL PROPERTY HEADLESS_RE_XDBG_RPC_INJECTION_SCHEDULED)
if(headless_re_rpc_injection_scheduled)
    return()
endif()
set_property(GLOBAL PROPERTY HEADLESS_RE_XDBG_RPC_INJECTION_SCHEDULED TRUE)

if(NOT DEFINED HEADLESS_RE_XDBG_RPC_SOURCE_DIR)
    message(FATAL_ERROR "HEADLESS_RE_XDBG_RPC_SOURCE_DIR is required")
endif()

function(headless_re_inject_xdbg_rpc)
    if(NOT TARGET headless)
        message(FATAL_ERROR "official x64dbg headless target is unavailable")
    endif()

    set(rpc_source_dir "${HEADLESS_RE_XDBG_RPC_SOURCE_DIR}")
    target_sources(headless PRIVATE
        "${rpc_source_dir}/headless_rpc.h"
        "${rpc_source_dir}/rpc_internal.h"
        "${rpc_source_dir}/rpc_events.cpp"
        "${rpc_source_dir}/rpc_methods.cpp"
        "${rpc_source_dir}/rpc_server.cpp"
    )
    target_include_directories(headless PRIVATE
        "${rpc_source_dir}"
        "${CMAKE_SOURCE_DIR}/src/bridge"
        "${CMAKE_SOURCE_DIR}/src/dbg"
        "${CMAKE_SOURCE_DIR}/src/dbg/jansson"
    )
    target_compile_definitions(headless PRIVATE
        HEADLESS_RE_XDBG_RPC=1
        NOMINMAX
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_libraries(headless PRIVATE
            "${CMAKE_SOURCE_DIR}/src/dbg/jansson/jansson_x86.lib"
        )
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_libraries(headless PRIVATE
            "${CMAKE_SOURCE_DIR}/src/dbg/jansson/jansson_x64.lib"
        )
    else()
        message(FATAL_ERROR "unsupported x64dbg architecture")
    endif()
endfunction()

cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}" CALL headless_re_inject_xdbg_rpc)