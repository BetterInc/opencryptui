cmake_minimum_required(VERSION 3.14)
project(OpenCryptUI LANGUAGES CXX)

# Enable position-independent code globally
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

# Check for CI environment
if(DEFINED ENV{CI} OR DEFINED ENV{GITHUB_ACTIONS} OR DEFINED ENV{GITLAB_CI} OR DEFINED ENV{TRAVIS})
    message(STATUS "Building in CI environment - disabling logs")
    add_definitions(-DQT_CI_BUILD)
    # Disable Qt debug/warning messages in CI
    add_definitions(-DQT_NO_DEBUG_OUTPUT)
    add_definitions(-DQT_NO_WARNING_OUTPUT)
endif()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt packages
find_package(Qt5 COMPONENTS Core Gui Widgets Test REQUIRED)

# OpenSSL configuration
if(WIN32)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_MSVC_STATIC_RT TRUE)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded") # Static runtime
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a") # Force static libraries
endif()

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Find Argon2 and Sodium (Scrypt) packages
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_search_module(ARGON2 REQUIRED libargon2)
    pkg_search_module(SODIUM REQUIRED libsodium)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(ARGON2_LIB_DIR $ENV{ARGON2_LIB_DIR})
    set(ARGON2_INCLUDE_DIR $ENV{ARGON2_INCLUDE_DIR})
    set(SODIUM_LIB_DIR $ENV{SODIUM_LIB_DIR})
    set(SODIUM_INCLUDE_DIR $ENV{SODIUM_INCLUDE_DIR})
    set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR})
    set(OPENSSL_INCLUDE_DIR $ENV{OPENSSL_INCLUDE_DIR})
    set(OPENSSL_LIBRARIES $ENV{OPENSSL_LIBRARIES})
    link_directories(${ARGON2_LIB_DIR} ${SODIUM_LIB_DIR})
    
    # Find macOS Security framework
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(ARGON2_LIB_DIR $ENV{ARGON2_LIB_DIR})
    set(ARGON2_INCLUDE_DIR $ENV{ARGON2_INCLUDE_DIR})
    set(SODIUM_LIB_DIR $ENV{SODIUM_LIB_DIR})
    set(SODIUM_INCLUDE_DIR $ENV{SODIUM_INCLUDE_DIR})
    link_directories(${ARGON2_LIB_DIR} ${SODIUM_LIB_DIR})
endif()

# Add this line to set the UI file directory
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui)

# Add the resources file
qt5_add_resources(RESOURCES resources/resources.qrc)

# Library sources
set(LIBRARY_SOURCES
    src/mainwindow.cpp
    src/mainwindow_menu.cpp
    src/mainwindow_preferences.cpp
    src/mainwindow_fileops.cpp
    include/mainwindow.h
    src/mainwindow_disk.cpp
    src/mainwindow_entropy.cpp
    src/encryptionengine_init.cpp
    src/encryptionengine_fileops.cpp
    src/encryptionengine_keyderivation.cpp
    src/encryptionengine_keyfile.cpp
    src/encryptionengine_crypto.cpp
    src/encryptionengine_tables.cpp
    src/encryptionengine_disk.cpp
    src/encryptionengine_diskops.cpp
    src/encryptionengine_diskops_header.cpp
    src/encryptionengine_tamperevidence.cpp
    src/encryptionengine_securewipe.cpp
    include/encryptionengine.h
    include/encryptionengine_diskops.h
    src/encryptionworker.cpp
    include/encryptionworker.h
    src/customlistwidget.cpp
    include/customlistwidget.h
    src/logging/secure_logger.cpp
    include/logging/secure_logger.h
    include/cryptoprovider.h
    src/opensslprovider.cpp
    src/opensslprovider_standard.cpp
    src/opensslprovider_aead.cpp
    src/libsodiumprovider.cpp
    src/argon2provider.cpp
    ui/mainwindow.ui
    ${RESOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/version.h
)

# Create a library target for common code
add_library(EncryptionLib STATIC ${LIBRARY_SOURCES})
set_target_properties(EncryptionLib PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(EncryptionLib PRIVATE -fPIC)

target_include_directories(EncryptionLib PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include/logging
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${Qt5Core_INCLUDE_DIRS}
    ${Qt5Gui_INCLUDE_DIRS}
    ${Qt5Widgets_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(EncryptionLib PRIVATE 
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ARGON2_LIBRARIES}
    ${SODIUM_LIBRARIES}
    argon2
    sodium
)

# Add Security framework on macOS
if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(EncryptionLib PRIVATE ${SECURITY_FRAMEWORK})
endif()

# Create the main executable and link against the library.
# WIN32 → no console window on Windows.
# MACOSX_BUNDLE → produce a proper OpenCryptUI.app on macOS so macdeployqt
# can embed Qt frameworks + plugins and the result runs on other Macs.
add_executable(OpenCryptUI WIN32 MACOSX_BUNDLE src/main.cpp)
set_target_properties(OpenCryptUI PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.opencryptui.OpenCryptUI"
    MACOSX_BUNDLE_BUNDLE_VERSION "1.0"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0"
)

target_compile_options(OpenCryptUI PRIVATE -fPIC)

# Disable logging for main application
target_compile_definitions(OpenCryptUI PRIVATE
    -DNO_LOGGING
)

target_include_directories(OpenCryptUI PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${Qt5Core_INCLUDE_DIRS}
    ${Qt5Gui_INCLUDE_DIRS}
    ${Qt5Widgets_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(OpenCryptUI PRIVATE EncryptionLib)

# Ensure GenerateVersionHeader is built before the main executable
add_dependencies(OpenCryptUI GenerateVersionHeader)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(PYTHON_EXECUTABLE ${PYTHON_EXECUTABLE})

# Add custom command to generate version.h using Python script
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.h
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_version_header.py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_version_header.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Add custom target to ensure version.h is generated
add_custom_target(GenerateVersionHeader ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/version.h)

# Include version.h
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Add test source
set(TEST_SOURCES
    tests/main.cpp
    tests/test_encryption_app.cpp
)

# Create test executable
add_executable(OpenCryptUITest ${TEST_SOURCES})
set_target_properties(OpenCryptUITest PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(OpenCryptUITest PRIVATE -fPIC)

# Always enable logging for tests
target_compile_definitions(OpenCryptUITest PRIVATE
    -DTEST_MODE
    -DENABLE_LOGGING
)

target_include_directories(OpenCryptUITest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${Qt5Core_INCLUDE_DIRS}
    ${Qt5Gui_INCLUDE_DIRS}
    ${Qt5Widgets_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    # Needed on macOS (Homebrew) and Windows (MSYS2) where sodium/argon2
    # headers aren't on the default search path. Linux picks them up from
    # /usr/include but listing them here is harmless.
    ${SODIUM_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIR}
    ${ARGON2_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIR}
)

target_link_libraries(OpenCryptUITest PRIVATE 
    EncryptionLib
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Test
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ARGON2_LIBRARIES}
    ${SODIUM_LIBRARIES}
    argon2
    sodium
)

# Roundtrip regression test — standalone binary, no UI.
# Guards against the sign/verify aliasing + trailer-format bugs fixed previously:
# a quick encrypt→decrypt must succeed and the recovered plaintext must match.
add_executable(TestRoundtrip tests/test_roundtrip.cpp)
set_target_properties(TestRoundtrip PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(TestRoundtrip PRIVATE -DTEST_MODE -DENABLE_LOGGING)
target_include_directories(TestRoundtrip PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/logging
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${Qt5Core_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIR}
    ${ARGON2_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIR}
)
target_link_libraries(TestRoundtrip PRIVATE
    EncryptionLib
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    OpenSSL::SSL
    OpenSSL::Crypto
    argon2
    sodium
)

# Helper macro: compile an engine-level test (no UI). One .cpp, one
# executable, one CTest entry. Matches the TestRoundtrip pattern so
# every engine test gets the same includes and links.
function(add_engine_test name source)
    add_executable(${name} ${source})
    set_target_properties(${name} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_definitions(${name} PRIVATE -DTEST_MODE -DENABLE_LOGGING)
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/logging
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${Qt5Core_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${SODIUM_INCLUDE_DIRS}
        ${SODIUM_INCLUDE_DIR}
        ${ARGON2_INCLUDE_DIRS}
        ${ARGON2_INCLUDE_DIR}
    )
    target_link_libraries(${name} PRIVATE
        EncryptionLib
        Qt5::Core Qt5::Gui Qt5::Widgets
        OpenSSL::SSL OpenSSL::Crypto
        argon2 sodium
    )
endfunction()

add_engine_test(TestEngineTamper        tests/test_engine_tamper.cpp)
add_engine_test(TestEngineDowngrade     tests/test_engine_downgrade.cpp)
add_engine_test(TestEngineKeyfile       tests/test_engine_keyfile.cpp)
add_engine_test(TestEngineCipherMatrix  tests/test_engine_cipher_matrix.cpp)
add_engine_test(TestEngineKdf           tests/test_engine_kdf.cpp)
add_engine_test(TestBenchmark           tests/test_benchmark.cpp)

# Add tests to CTest
enable_testing()
add_test(NAME OpenCryptUITest       COMMAND OpenCryptUITest)
add_test(NAME TestRoundtripGCM      COMMAND TestRoundtrip AES-256-GCM)
add_test(NAME TestRoundtripCBC      COMMAND TestRoundtrip AES-256-CBC)
add_test(NAME EngineTamper          COMMAND TestEngineTamper)
add_test(NAME EngineDowngrade       COMMAND TestEngineDowngrade)
add_test(NAME EngineKeyfile         COMMAND TestEngineKeyfile)
add_test(NAME EngineCipherMatrix    COMMAND TestEngineCipherMatrix)
add_test(NAME EngineKdf             COMMAND TestEngineKdf)
add_test(NAME TestBenchmark         COMMAND TestBenchmark)

# Copy test runner scripts
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_tests.sh
    ${CMAKE_CURRENT_BINARY_DIR}/run_tests.sh
    COPYONLY
)
# Make the scripts executable
file(CHMOD ${CMAKE_CURRENT_BINARY_DIR}/run_tests.sh 
     PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Copy macOS-specific test script
if(APPLE)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_tests_mac.sh
        ${CMAKE_CURRENT_BINARY_DIR}/run_tests_mac.sh
        COPYONLY
    )
    # Make the macOS script executable
    file(CHMOD ${CMAKE_CURRENT_BINARY_DIR}/run_tests_mac.sh 
         PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

# Copy Windows-specific test script
if(WIN32)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/run_tests.bat
        ${CMAKE_CURRENT_BINARY_DIR}/run_tests.bat
        COPYONLY
    )
endif()

# Print paths for debugging
message(STATUS "Qt5_DIR: ${Qt5_DIR}")
message(STATUS "OPENSSL_ROOT_DIR: ${OPENSSL_ROOT_DIR}")
message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message(STATUS "ARGON2_INCLUDE_DIRS: ${ARGON2_INCLUDE_DIRS}")
message(STATUS "SODIUM_INCLUDE_DIRS: ${SODIUM_INCLUDE_DIRS}")
message(STATUS "ARGON2_LIB_DIR: ${ARGON2_LIB_DIR}")
message(STATUS "SODIUM_LIB_DIR: ${SODIUM_LIB_DIR}")
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")