cmake_minimum_required(VERSION 3.16)
project(NetGuard VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include_directories(
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/agent
    ${CMAKE_SOURCE_DIR}/ui
)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Common C++ Sources
set(COMMON_SOURCES
    agent/NetlinkClient.cpp
    agent/RuleManager.cpp
    agent/Statistics.cpp
)

# 1. CLI Agent Executable
add_executable(netguard
    agent/main.cpp
    agent/CLI.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(netguard PRIVATE Threads::Threads)

# 2. X11 / Xft GUI NOC Dashboard
pkg_check_modules(X11_DEPS x11 xft freetype2)
if(X11_DEPS_FOUND)
    add_executable(netguard-gui
        ui/gui_main.cpp
        ui/NetGuardGUI.cpp
        ui/X11Canvas.cpp
        ${COMMON_SOURCES}
    )
    target_include_directories(netguard-gui PRIVATE ${X11_DEPS_INCLUDE_DIRS})
    target_link_libraries(netguard-gui PRIVATE ${X11_DEPS_LIBRARIES} Threads::Threads)
endif()

# 3. NCurses Terminal Dashboard (TUI)
pkg_check_modules(NCURSES REQUIRED ncurses)
add_executable(netguard-tui
    ui/tui_main.cpp
    ui/NetGuardTUI.cpp
    ${COMMON_SOURCES}
)
target_include_directories(netguard-tui PRIVATE ${NCURSES_INCLUDE_DIRS})
target_link_libraries(netguard-tui PRIVATE ${NCURSES_LIBRARIES} Threads::Threads)

# 4. Unit Test Suite
add_executable(netguard-tests
    tests/test_main.cpp
    tests/test_rules.cpp
    tests/test_parser.cpp
    tests/test_netlink_proto.cpp
    ${COMMON_SOURCES}
)
target_link_libraries(netguard-tests PRIVATE Threads::Threads)

# 5. Custom Target for Linux Kernel Module
add_custom_target(kernel_module ALL
    COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_SOURCE_DIR}/kernel
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building NetGuard Linux Kernel Module"
)
