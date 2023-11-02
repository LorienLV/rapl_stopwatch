cmake_minimum_required(VERSION 3.5)

project(rapl_stopwatch VERSION 1.0.0 LANGUAGES C CXX)

option(BUILD_TESTS "Build unit tests" OFF)

include(GNUInstallDirs)

add_library(${PROJECT_NAME} src/rapl_stopwatch.c)

target_include_directories(${PROJECT_NAME} 
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}>
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    PUBLIC_HEADER 
        "include/rapl_stopwatch.h"
)

if (BUILD_SHARED_LIBS)
    set_target_properties(${PROJECT_NAME} PROPERTIES 
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

# Link against pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

