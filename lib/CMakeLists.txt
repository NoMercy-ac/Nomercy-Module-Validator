cmake_minimum_required(VERSION 3.8)
project(NoMercyModuleValidator CXX)

add_library (${PROJECT_NAME}
    STATIC
    include/NoMercyValidator.h
    src/main.cpp
)

target_link_libraries(
	${PROJECT_NAME}
	crypt32
	wintrust
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)
