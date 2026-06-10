# The C codec: the interposer's half of the wire protocol (see ../SPEC.md).
add_library(se_protocol STATIC
  src/se_protocol.c
  src/se_framing.c
)
target_include_directories(se_protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# The codec unit test is a pure host-slice check.
if(NOT SIMENCLAVE_SIM_SLICE)
  add_executable(protocol_test tests/protocol_test.c)
  target_link_libraries(protocol_test PRIVATE se_protocol)
  add_test(NAME protocol_codec COMMAND protocol_test)
endif()
