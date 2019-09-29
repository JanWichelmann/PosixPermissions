# Pick CMake version
cmake_minimum_required(VERSION 3.12)

# General project metadata
project(
	PosixPermissionsNative
	VERSION 1.0
    DESCRIPTION "Wrapper for access to native ACL functions"
	LANGUAGES C
)

# Check dependencies
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(ACL REQUIRED) # ACL_LIBS   # TODO this does not fail properly, see https://stackoverflow.com/q/58144866/8528014

# Build as shared library
add_library(
	aclnative
	SHARED
		src/acl_native.c
)
target_include_directories(
	aclnative
	PUBLIC
		include/
)
target_compile_features(
	aclnative
	PUBLIC
		c_std_11
)
target_link_libraries(
	aclnative
	PUBLIC
		${ACL_LIBS}
)
