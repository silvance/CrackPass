cmake_minimum_required(VERSION 3.24)
project(hashcat-gui CXX)

# Set version
set(GUI_VERSION 0.7.1)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h
    @ONLY
)

# Build in Release mode by default
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type specified - defaulting to Release")
    set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "Building with CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

# Need at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Qt specific preprocessing
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets Concurrent Test REQUIRED)

# ---------------------------------------------------------------------------
# forensic_core: all non-UI Forensic Mode logic. Depends on Qt6::Core only so
# it can be unit-tested without a GUI, and so upstream UI code stays separate.
# ---------------------------------------------------------------------------
add_library(forensic_core STATIC
    src/forensic/artifacttype.h
    src/forensic/artifactanalyzer.h
    src/forensic/magicbyteanalyzer.h
    src/forensic/magicbyteanalyzer.cpp
    src/forensic/artifactanalyzerregistry.h
    src/forensic/artifactanalyzerregistry.cpp
    src/forensic/hashextractor.h
    src/forensic/builtinextractors.h
    src/forensic/builtinextractors.cpp
    src/forensic/extractorregistry.h
    src/forensic/extractorregistry.cpp
    src/forensic/hashingservice.h
    src/forensic/hashingservice.cpp
    src/forensic/jsonutil.h
    src/forensic/evidenceitem.h
    src/forensic/evidenceitem.cpp
    src/forensic/evidenceintake.h
    src/forensic/evidenceintake.cpp
    src/forensic/caseinfo.h
    src/forensic/caseinfo.cpp
    src/forensic/caseworkspace.h
    src/forensic/caseworkspace.cpp
    src/forensic/crackingjob.h
    src/forensic/crackingjob.cpp
    src/forensic/recoveredcredential.h
    src/forensic/recoveredcredential.cpp
    src/forensic/auditlog.h
    src/forensic/auditlog.cpp
)
target_include_directories(forensic_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(forensic_core PUBLIC Qt6::Core)
target_compile_options(forensic_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(hashcat-gui WIN32
    src/aboutdialog.h
    src/aboutdialog.cpp
    src/helperutils.h
    src/helperutils.cpp
    src/main.cpp
    src/mainwindow.h
    src/mainwindow.cpp
    src/settingsdialog.h
    src/settingsdialog.cpp
    src/settingsmanager.h
    src/settingsmanager.cpp
    src/widgetstateserializer.h
    src/widgetstateserializer.cpp
    src/ui/appshell.h
    src/ui/appshell.cpp
    src/ui/forensicwindow.h
    src/ui/forensicwindow.cpp
    src/resources.qrc
    src/hashcat-gui.rc
    src/aboutdialog.ui
    src/mainwindow.ui
    src/settingsdialog.ui
)

target_compile_options(hashcat-gui PRIVATE -Wall -Wextra -Wpedantic)

target_link_libraries(hashcat-gui PRIVATE forensic_core Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Concurrent)

install(TARGETS hashcat-gui RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Unit tests (non-UI logic). Run with: ctest --test-dir build
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
