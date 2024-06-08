cmake_minimum_required(VERSION 3.8)
project(NoMercyValidatorTest CXX)

add_executable (${PROJECT_NAME}
    src/main.cpp
)

target_link_libraries(
	${PROJECT_NAME}
	NoMercyModuleValidator
)
