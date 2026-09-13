cmake_minimum_required(VERSION 3.24)
project(casekey CXX)

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
    src/forensic/extractorregistry.h
    src/forensic/extractorregistry.cpp
    src/forensic/extraction/hashcatmodes.h
    src/forensic/extraction/moderesolution.h
    src/forensic/extraction/moderesolution.cpp
    src/forensic/extraction/processrunner.h
    src/forensic/extraction/processrunner.cpp
    src/forensic/extraction/toolresolver.h
    src/forensic/extraction/encryptionprobe.h
    src/forensic/extraction/encryptionprobe.cpp
    src/forensic/extraction/john2hashextractor.h
    src/forensic/extraction/john2hashextractor.cpp
    src/forensic/extraction/johnextractors.h
    src/forensic/extraction/extraction.h
    src/forensic/extraction/extraction.cpp
    src/forensic/planner/caseknowledge.h
    src/forensic/planner/attacktemplate.h
    src/forensic/planner/attacktemplate.cpp
    src/forensic/planner/attackjobspec.h
    src/forensic/planner/attackjobspec.cpp
    src/forensic/planner/attackcommandbuilder.h
    src/forensic/planner/attackcommandbuilder.cpp
    src/forensic/planner/johncommandbuilder.h
    src/forensic/planner/johncommandbuilder.cpp
    src/forensic/planner/knowledgematerializer.h
    src/forensic/planner/knowledgematerializer.cpp
    src/forensic/planner/attackpreview.h
    src/forensic/planner/attackplanner.h
    src/forensic/planner/attackplanner.cpp
    src/forensic/execution/hashcatstatus.h
    src/forensic/execution/hashcatstatusparser.h
    src/forensic/execution/hashcatstatusparser.cpp
    src/forensic/execution/hashcatstatusstream.h
    src/forensic/execution/hashcatstatusstream.cpp
    src/forensic/execution/crackedplain.h
    src/forensic/execution/crackedplain.cpp
    src/forensic/execution/jobexecutionbackend.h
    src/forensic/execution/jobqueue.h
    src/forensic/execution/jobqueue.cpp
    src/forensic/execution/hashcatexecutionbackend.h
    src/forensic/execution/hashcatexecutionbackend.cpp
    src/forensic/execution/johnexecutionbackend.h
    src/forensic/execution/johnexecutionbackend.cpp
    src/forensic/report/recoveryreport.h
    src/forensic/report/recoveryreport.cpp
    src/forensic/report/reportbuilder.h
    src/forensic/report/reportbuilder.cpp
    src/forensic/report/reportrenderer.h
    src/forensic/report/reportrenderer.cpp
    src/forensic/hashingservice.h
    src/forensic/hashingservice.cpp
    src/forensic/jsonutil.h
    src/forensic/atomicwrite.h
    src/forensic/deps/dependencyprobe.h
    src/forensic/deps/dependencyprobe.cpp
    src/forensic/deps/toolchainservice.h
    src/forensic/deps/toolchainservice.cpp
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
    src/forensic/casetransaction.h
    src/forensic/casetransaction.cpp
    src/forensic/recovery/recoverycontroller.h
    src/forensic/recovery/recoverycontroller.cpp
    src/forensic/recovery/recoveryengine.h
    src/forensic/recovery/recoveryengineregistry.h
    src/forensic/recovery/recoveryengineregistry.cpp
)
target_include_directories(forensic_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(forensic_core PUBLIC Qt6::Core)
# Warning flags are compiler-specific: -W* are GCC/Clang spellings that MSVC's
# cl.exe rejects (it reads /Wextra as an invalid /W argument), so gate them.
target_compile_options(forensic_core PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>)

add_executable(casekey WIN32
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
    src/ui/attackplannerdialog.h
    src/ui/attackplannerdialog.cpp
    src/ui/forensicsettingsdialog.h
    src/ui/forensicsettingsdialog.cpp
    src/ui/dependencydoctordialog.h
    src/ui/dependencydoctordialog.cpp
    src/resources.qrc
    src/hashcat-gui.rc
    src/aboutdialog.ui
    src/mainwindow.ui
    src/settingsdialog.ui
)

target_compile_options(casekey PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>)

target_link_libraries(casekey PRIVATE forensic_core Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Concurrent)

install(TARGETS casekey RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Unit tests (non-UI logic). Run with: ctest --test-dir build
# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
