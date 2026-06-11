# The interposer core: hooks, shadow-ref registry, loopback transport, and the
# hook backend. No load constructor here; the dylib and the host harness add
# their own entry point, so both reuse this.
add_library(interpose_core STATIC
  src/hooks/sec_key_hooks.c
  src/registry/shadow_ref.c
  src/registry/access_control.c
  src/transport/client.c
  src/backend/dobby_backend.c
)
target_include_directories(interpose_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(interpose_core PUBLIC se_protocol dobby_bundle)

set(SE_FRAMEWORKS "-framework Security" "-framework CoreFoundation")

if(SIMENCLAVE_SIM_SLICE)
  # The injectable dylib: the core plus the dyld load constructor.
  add_library(simenclave_interpose SHARED src/entry.c)
  set_target_properties(simenclave_interpose PROPERTIES PREFIX "" OUTPUT_NAME simenclave-interpose)
  target_link_libraries(simenclave_interpose PRIVATE interpose_core ${SE_FRAMEWORKS})

  # The in-simulator demo links no interposer; it is injected at spawn.
  add_executable(sim_demo tests/sim_demo.c)
  target_link_libraries(sim_demo PRIVATE ${SE_FRAMEWORKS})
else()
  # Mechanism C: the host harness that installs the hooks in-process and proves
  # they route to the helper. The run-mechanism-c.sh script drives it.
  add_executable(mechanism_c tests/mechanism_c.c)
  target_link_libraries(mechanism_c PRIVATE interpose_core ${SE_FRAMEWORKS})

  # The client round-trip: the transport driving all four wire ops against the
  # helper directly, no hooks. The same script runs it after mechanism C.
  add_executable(client_roundtrip tests/client_roundtrip.c)
  target_include_directories(client_roundtrip PRIVATE src/transport)
  target_link_libraries(client_roundtrip PRIVATE interpose_core ${SE_FRAMEWORKS})

  # The Dobby smoke test stands alone.
  add_executable(hook_smoke tests/hook_smoke.c)
  target_link_libraries(hook_smoke PRIVATE dobby_bundle ${SE_FRAMEWORKS})
  add_test(NAME hook_smoke COMMAND hook_smoke)

  # The passthrough invariant: a non-SE keychain call is byte-identical with the
  # hooks installed. No helper, so it runs as a plain ctest.
  add_executable(passthrough_test tests/passthrough_test.c)
  target_link_libraries(passthrough_test PRIVATE interpose_core ${SE_FRAMEWORKS})
  add_test(NAME passthrough COMMAND passthrough_test)
endif()
