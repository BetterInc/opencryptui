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

# ---------------------------------------------------------------------------
# Compiler / linker hardening flags.
#
# We feature-detect each flag so gcc/clang/MinGW/AppleClang are all happy.
# Flags are collected into ENGINE_HARDENING_CFLAGS / ENGINE_HARDENING_LFLAGS
# and applied to our own targets below (NOT globally — we don't want to
# break Qt/Sodium/OpenSSL transitively). For the final STATUS summary we
# also collect enabled flags into ENGINE_HARDENING_SUMMARY.
#
# Applies to: EncryptionLib, OpenCryptUI, OpenCryptUITest, TestRoundtrip,
#             and every TestEngine* / TestBenchmark target created via the
#             add_engine_test() helper later in this file.
#
# Target profile:
#   - Stack overflow / smash: -fstack-protector-strong, -fstack-clash-protection
#   - FORTIFY source (libc): -D_FORTIFY_SOURCE=2 (only active at -O2+)
#   - CFI via Intel CET on x86-64: -fcf-protection=full (no-op on non-x86)
#   - Format-string auditing: -Wformat -Wformat-security -Werror=format-security
#   - Linker: RELRO + BIND_NOW + noexecstack (ELF only), -pie (ELF only)
# ---------------------------------------------------------------------------
include(CheckCXXCompilerFlag)

set(ENGINE_HARDENING_CFLAGS "")
set(ENGINE_HARDENING_LFLAGS "")
set(ENGINE_HARDENING_SUMMARY "")

function(_try_add_cflag flag var_name)
    string(MAKE_C_IDENTIFIER "has${flag}" _sym)
    # Apple Clang silently accepts many GCC-only flags (e.g.
    # -fstack-clash-protection) and emits "argument unused during
    # compilation" once per translation unit. Forcing
    # -Werror=unused-command-line-argument during the probe makes those
    # cases fail the check so we don't add a no-op-with-warning flag.
    #
    # Only do this on Clang — gcc doesn't recognise that diagnostic
    # name, so passing -Werror=unused-command-line-argument to gcc
    # causes every probe to fail.
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(CMAKE_REQUIRED_FLAGS "-Werror=unused-command-line-argument")
    endif()
    check_cxx_compiler_flag("${flag}" ${_sym})
    unset(CMAKE_REQUIRED_FLAGS)
    if(${_sym})
        list(APPEND ENGINE_HARDENING_CFLAGS "${flag}")
        list(APPEND ENGINE_HARDENING_SUMMARY "${flag}")
        set(ENGINE_HARDENING_CFLAGS "${ENGINE_HARDENING_CFLAGS}" PARENT_SCOPE)
        set(ENGINE_HARDENING_SUMMARY "${ENGINE_HARDENING_SUMMARY}" PARENT_SCOPE)
    endif()
endfunction()

# Compile-time flags. FORTIFY_SOURCE only makes sense at -O2+; set it via
# a generator expression so Debug builds don't warn about "requires optimization".
_try_add_cflag("-fstack-protector-strong"     stackprot_strong)
_try_add_cflag("-fstack-clash-protection"     stackclash)
_try_add_cflag("-fcf-protection=full"         cfprot)
_try_add_cflag("-Wformat"                     wformat)
_try_add_cflag("-Wformat-security"            wformat_sec)
_try_add_cflag("-Werror=format-security"      werr_format_sec)

# FORTIFY_SOURCE needs optimization; attach it to Release-like configs only.
# Use -D form so it reaches the preprocessor explicitly.
set(ENGINE_HARDENING_FORTIFY
    "$<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>"
    "$<$<CONFIG:RelWithDebInfo>:-D_FORTIFY_SOURCE=2>"
    "$<$<CONFIG:MinSizeRel>:-D_FORTIFY_SOURCE=2>"
)
list(APPEND ENGINE_HARDENING_SUMMARY "-D_FORTIFY_SOURCE=2 (Release configs)")

# Linker flags: ELF-only. Skip on macOS (ld64 doesn't accept these) and
# skip if the compile-flag probe above failed to find a C++ compiler.
if(NOT APPLE AND NOT MSVC)
    set(_linker_candidates
        "-Wl,-z,relro"
        "-Wl,-z,now"
        "-Wl,-z,noexecstack"
    )
    foreach(_lflag IN LISTS _linker_candidates)
        # Probe by trying to compile+link a trivial program. CMake's
        # check_linker_flag is 3.18+; support older via try_compile probe.
        set(_tmp_src "${CMAKE_BINARY_DIR}/_hardening_probe.cpp")
        file(WRITE "${_tmp_src}" "int main(){return 0;}\n")
        try_compile(_ok "${CMAKE_BINARY_DIR}/_hardening_try" "${_tmp_src}"
            LINK_OPTIONS "${_lflag}"
            OUTPUT_VARIABLE _out)
        if(_ok)
            list(APPEND ENGINE_HARDENING_LFLAGS "${_lflag}")
            list(APPEND ENGINE_HARDENING_SUMMARY "${_lflag}")
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------

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
    
    # macOS frameworks. Security for keychain/SE/CryptoKit hooks (used by
    # hwkey_macos.cpp); CoreFoundation for the CF* types Security drags in
    # (CFDictionary, CFRelease, kCFAllocatorDefault — these are NOT in
    # Security itself, contrary to many docs).
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
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
    src/encryptionengine_chunks.cpp
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
    src/secure_string.cpp
    include/secure_string.h
    src/hwkey_stub.cpp
    src/hwkey_linux.cpp
    src/hwkey_macos.cpp
    src/hwkey_windows.cpp
    include/hwkey.h
    src/pq_hybrid.cpp
    src/pq_hybrid_stub.cpp
    include/pq_hybrid.h
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

target_compile_options(EncryptionLib PRIVATE -fPIC
    ${ENGINE_HARDENING_CFLAGS}
    ${ENGINE_HARDENING_FORTIFY}
)
target_link_options(EncryptionLib PRIVATE ${ENGINE_HARDENING_LFLAGS})

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
    target_link_libraries(EncryptionLib PRIVATE ${SECURITY_FRAMEWORK} ${COREFOUNDATION_FRAMEWORK})
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

target_compile_options(OpenCryptUI PRIVATE -fPIC
    ${ENGINE_HARDENING_CFLAGS}
    ${ENGINE_HARDENING_FORTIFY}
)
target_link_options(OpenCryptUI PRIVATE ${ENGINE_HARDENING_LFLAGS})

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
    tests/test_ui_encrypt_decrypt.cpp
    tests/test_ui_smoke.cpp
    tests/test_ui_tamper.cpp
    tests/test_ui_common.h
)

# Create test executable
add_executable(OpenCryptUITest ${TEST_SOURCES})
set_target_properties(OpenCryptUITest PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(OpenCryptUITest PRIVATE -fPIC
    ${ENGINE_HARDENING_CFLAGS}
    ${ENGINE_HARDENING_FORTIFY}
)
target_link_options(OpenCryptUITest PRIVATE ${ENGINE_HARDENING_LFLAGS})

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
target_compile_options(TestRoundtrip PRIVATE
    ${ENGINE_HARDENING_CFLAGS}
    ${ENGINE_HARDENING_FORTIFY}
)
target_link_options(TestRoundtrip PRIVATE ${ENGINE_HARDENING_LFLAGS})

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
    target_compile_options(${name} PRIVATE
        ${ENGINE_HARDENING_CFLAGS}
        ${ENGINE_HARDENING_FORTIFY}
    )
    target_link_options(${name} PRIVATE ${ENGINE_HARDENING_LFLAGS})
endfunction()

add_engine_test(TestEngineTamper        tests/test_engine_tamper.cpp)
add_engine_test(TestEngineDowngrade     tests/test_engine_downgrade.cpp)
add_engine_test(TestEngineKeyfile       tests/test_engine_keyfile.cpp)
add_engine_test(TestEngineCipherMatrix  tests/test_engine_cipher_matrix.cpp)
add_engine_test(TestEngineKdf           tests/test_engine_kdf.cpp)
add_engine_test(TestBenchmark           tests/test_benchmark.cpp)
add_engine_test(TestEnginePerChunk      tests/test_engine_per_chunk.cpp)
add_engine_test(TestSecureString        tests/test_secure_string.cpp)
add_engine_test(TestSecureLoggerRedact  tests/test_secure_logger_redaction.cpp)
add_engine_test(TestPqHybrid            tests/test_pq_hybrid.cpp)
add_engine_test(TestHwKeyStub           tests/test_hwkey_stub.cpp)

# End-to-end black-box test: exercises the shipped OpenCryptUI binary via
# QProcess (startup smoke) plus engine round-trip and tamper-rejection cases
# that mirror what the binary does at runtime.
add_engine_test(TestEndToEndBlackbox    tests/test_endtoend_blackbox.cpp)
# Inject the absolute path to the OpenCryptUI binary so the test can locate
# it without relying on PATH or working-directory assumptions.
target_compile_definitions(TestEndToEndBlackbox PRIVATE
    OPENCRYPTUI_BINARY_PATH="${CMAKE_BINARY_DIR}/OpenCryptUI"
)
# QProcess is part of Qt5::Core (already linked by add_engine_test), but
# ensure the dependency on the binary being built is expressed so that a
# parallel build does not run the test before the binary is ready.
add_dependencies(TestEndToEndBlackbox OpenCryptUI)

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
add_test(NAME EnginePerChunk        COMMAND TestEnginePerChunk)
add_test(NAME SecureString          COMMAND TestSecureString)
add_test(NAME SecureLoggerRedact    COMMAND TestSecureLoggerRedact)
add_test(NAME PqHybrid              COMMAND TestPqHybrid)
add_test(NAME HwKeyStub             COMMAND TestHwKeyStub)
add_test(NAME EndToEndBlackbox      COMMAND TestEndToEndBlackbox)
set_tests_properties(EndToEndBlackbox PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    TIMEOUT 30
)

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

message(STATUS "=== Hardening summary ===")
if(ENGINE_HARDENING_SUMMARY)
    foreach(_s IN LISTS ENGINE_HARDENING_SUMMARY)
        message(STATUS "  ${_s}")
    endforeach()
else()
    message(STATUS "  (no hardening flags enabled — compiler too old or on an unsupported platform)")
endif()

# ---------------------------------------------------------------------------
# Reproducible-build provenance.
#
# Goal: a security researcher can build OpenCryptUI from source, hash the
# binary, and compare against a published reference. Two unrelated builds
# of the same commit should produce byte-identical output.
#
# What we do here:
#   - Pick up SOURCE_DATE_EPOCH from the commit timestamp if not already in
#     the environment. GCC, ld, and other tooling honour this to suppress
#     embedded build timestamps.
#   - Add -Wl,--build-id=sha1 (ELF only) so the build-id is a deterministic
#     hash of the input rather than a random uuid.
#   - Emit BUILD_PROVENANCE.txt next to the binary with everything a
#     reviewer needs to verify the build: commit, epoch, dep versions,
#     compiler version, hardening flag set actually applied.
# ---------------------------------------------------------------------------
if(NOT DEFINED ENV{SOURCE_DATE_EPOCH})
    execute_process(
        COMMAND git -C ${CMAKE_SOURCE_DIR} log -1 --format=%ct
        OUTPUT_VARIABLE _git_epoch
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _git_rc)
    if(_git_rc EQUAL 0 AND _git_epoch)
        set(ENV{SOURCE_DATE_EPOCH} "${_git_epoch}")
        message(STATUS "SOURCE_DATE_EPOCH: ${_git_epoch} (from git HEAD)")
    endif()
endif()

if(NOT APPLE AND NOT MSVC)
    foreach(_t EncryptionLib OpenCryptUI OpenCryptUITest TestRoundtrip)
        if(TARGET ${_t})
            target_link_options(${_t} PRIVATE -Wl,--build-id=sha1)
        endif()
    endforeach()
endif()

# Capture commit + dep versions for BUILD_PROVENANCE.txt
execute_process(COMMAND git -C ${CMAKE_SOURCE_DIR} rev-parse HEAD
    OUTPUT_VARIABLE OCUI_GIT_SHA OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET RESULT_VARIABLE _sha_rc)
if(NOT _sha_rc EQUAL 0)
    set(OCUI_GIT_SHA "unknown")
endif()

# Best-effort dep version detection.
set(OCUI_OPENSSL_VERSION  "${OPENSSL_VERSION}")
set(OCUI_SODIUM_VERSION   "${SODIUM_VERSION}")
set(OCUI_ARGON2_VERSION   "${ARGON2_VERSION}")
set(OCUI_QT5_VERSION      "${Qt5_VERSION}")
set(OCUI_COMPILER_ID      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

string(REPLACE ";" "\n  " OCUI_HARDENING_LIST "${ENGINE_HARDENING_SUMMARY}")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/BUILD_PROVENANCE.txt
"OpenCryptUI build provenance
=============================
Generated at configure time. Pair with the binary's SHA-256 to verify a build.

Commit               : ${OCUI_GIT_SHA}
SOURCE_DATE_EPOCH    : $ENV{SOURCE_DATE_EPOCH}
Compiler             : ${OCUI_COMPILER_ID}
CMake                : ${CMAKE_VERSION}
Build type           : ${CMAKE_BUILD_TYPE}
Target system        : ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}

Dependencies
------------
OpenSSL              : ${OCUI_OPENSSL_VERSION}
libsodium            : ${OCUI_SODIUM_VERSION}
Argon2               : ${OCUI_ARGON2_VERSION}
Qt5                  : ${OCUI_QT5_VERSION}

Hardening flags applied
-----------------------
  ${OCUI_HARDENING_LIST}
")
message(STATUS "Wrote ${CMAKE_CURRENT_BINARY_DIR}/BUILD_PROVENANCE.txt")