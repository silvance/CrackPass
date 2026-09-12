# Optional real-tool integration layer. It BUILDS by default (so it always
# compiles) but SKIPS at runtime when hashcat / *2john / the corpus are absent,
# so it never breaks normal unit-test builds. Requires no network access.

add_library(integration_support STATIC
    integrationenv.h
    integrationenv.cpp
    integrationchain.h
    integrationchain.cpp
)
target_link_libraries(integration_support PUBLIC forensic_core Qt6::Core)
target_include_directories(integration_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# QtTest wrapper: registered with CTest; QSKIPs cleanly without the tools.
add_executable(test_integration test_integration.cpp)
target_link_libraries(test_integration PRIVATE integration_support Qt6::Test)
add_test(NAME test_integration COMMAND test_integration)

# Standalone diagnostic runner for a disconnected workstation.
add_executable(crackpass_integration_diag diagnostics_main.cpp)
target_link_libraries(crackpass_integration_diag PRIVATE integration_support)
