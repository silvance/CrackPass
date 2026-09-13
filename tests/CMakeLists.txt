# Unit tests for the non-UI forensic core. Each file is a self-contained
# QtTest executable registered with CTest.

set(FORENSIC_TESTS
    test_hashingservice
    test_artifactanalyzer
    test_extractorregistry
    test_auditlog
    test_casetransaction
    test_caseworkspace
    test_datamodels
    test_moderesolution
    test_encryptionprobe
    test_zipcipher
    test_johnextractors
    test_extractionservice
    test_attackcommandbuilder
    test_johncommandbuilder
    test_bkcrackcommandbuilder
    test_johnbackend
    test_knowledgematerializer
    test_attackplanner
    test_hashcatstatusparser
    test_jobqueue
    test_bkcrackbackend
    test_jobpersistence
    test_backendcompose
    test_reportbuilder
    test_evidenceintegrity
    test_statusstream
    test_crackedplain
    test_dependencyprobe
    test_toolchainservice
    test_recoverycontroller
    test_recoveryengineregistry
)

foreach(test_name ${FORENSIC_TESTS})
    add_executable(${test_name} ${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE forensic_core Qt6::Core Qt6::Test)
    target_compile_options(${test_name} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra>
        $<$<CXX_COMPILER_ID:MSVC>:/W4>)
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Optional real-tool integration layer (compiles always; skips at runtime when
# external tools/corpus are absent). Disable with -DCASEKEY_BUILD_INTEGRATION=OFF.
option(CASEKEY_BUILD_INTEGRATION "Build the optional real-tool integration tests" ON)
if(CASEKEY_BUILD_INTEGRATION)
    add_subdirectory(integration)
endif()
