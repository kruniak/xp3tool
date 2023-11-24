cmake_minimum_required (VERSION 3.22)

project (xp3tool)

add_executable (xp3tool "xp3tool.c")

set_property(TARGET xp3tool PROPERTY C_STANDARD 99)

find_package(ZLIB REQUIRED)
target_link_libraries(xp3tool PRIVATE ZLIB::ZLIB)