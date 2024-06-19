cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

project (libmctp)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -Wall \
    -Wextra \
    -Wunused \
    -Wnull-dereference \
    -Wpointer-to-int-cast \
    -Wformat=2 \
")

# Remove if code fixes
set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
    -Wno-unused-parameter \
    -Wno-sign-compare \
    -Wno-type-limits \
")

add_definitions (-DMCTP_LOG_STDERR)
add_definitions (-DMCTP_HAVE_FILEIO)
add_definitions (-DMCTP_HAVE_STDIO)
add_definitions (-DMCTP_DEFAULT_ALLOC)

add_library (mctp_starfive STATIC alloc.c asti3c.c astlpc.c core.c log.c libmctp.h serial.c astpcie.c smbus.c starfive-i3c.c starfive-pcie.c)

target_include_directories (mctp_starfive PUBLIC
                            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
                            $<INSTALL_INTERFACE:include/libmctp>)

enable_testing ()

add_executable (test_eid tests/test_eid.c tests/test-utils.c)
target_link_libraries (test_eid mctp_starfive)
add_test (NAME eid COMMAND test_eid)

add_executable (test_seq tests/test_seq.c tests/test-utils.c)
target_link_libraries (test_seq mctp_starfive)
add_test (NAME seq COMMAND test_seq)

add_executable (test_bridge tests/test_bridge.c tests/test-utils.c)
target_link_libraries (test_bridge mctp_starfive)
add_test (NAME bridge COMMAND test_bridge)

add_executable (test_astlpc tests/test_astlpc.c tests/test-utils.c)
target_link_libraries (test_astlpc mctp_starfive)
add_test (NAME astlpc COMMAND test_astlpc)

add_executable (test_serial tests/test_serial.c tests/test-utils.c)
target_link_libraries (test_serial mctp_starfive)
add_test (NAME serial COMMAND test_serial)

add_executable (test_astpcie tests/test_astpcie.c)
target_link_options(test_astpcie PRIVATE -z muldefs)
target_link_libraries (test_astpcie mctp_starfive)
add_test (NAME astpcie COMMAND test_astpcie)

add_executable (test_cmds tests/test_cmds.c tests/test-utils.c)
target_link_libraries (test_cmds mctp_starfive)
add_test (NAME control_commands COMMAND test_cmds)

add_executable (test_smbus tests/test_smbus.c)
target_link_libraries (test_smbus mctp_starfive)
add_test (NAME smbus COMMAND test_smbus)

add_executable (test_binding_private tests/test_binding_private.c)
target_link_libraries (test_binding_private mctp_starfive)
add_test (NAME binding_private COMMAND test_binding_private)

add_executable (mctp_astpcie_discovery utils/mctp-astpcie-discovery.c)
target_link_libraries (mctp_astpcie_discovery mctp_starfive)

add_executable (test_encode_decode tests/test_encode_decode.c)
target_link_libraries (test_encode_decode mctp_starfive)
add_test (NAME encode_decode COMMAND test_encode_decode)

add_executable (mctp_astpcie_register_type utils/mctp-astpcie-register-type.c)
target_link_libraries (mctp_astpcie_register_type mctp_starfive)

add_executable (test_asti3c tests/test_asti3c.c)
target_link_libraries (test_asti3c mctp_starfive)
add_test (NAME asti3c COMMAND test_asti3c)

add_executable (test_starfive_i3c tests/test_starfive_i3c.c)
target_link_libraries (test_starfive_i3c mctp_starfive)
add_test (NAME starfive_i3c COMMAND test_starfive_i3c)

add_executable (mctp_starfive_pcie_discovery utils/mctp-starfive-pcie-discovery.c)
target_link_libraries (mctp_starfive_pcie_discovery mctp_starfive)

add_executable (mctp_starfive_pcie_register_type utils/mctp-starfive-pcie-register-type.c)
target_link_libraries (mctp_starfive_pcie_register_type mctp_starfive)

add_executable (test_starfive_pcie tests/test_starfive_pcie.c)
target_link_options(test_starfive_pcie PRIVATE -z muldefs)
target_link_libraries (test_starfive_pcie mctp_starfive)
add_test (NAME starfive_pcie COMMAND test_starfive_pcie)

install (TARGETS mctp_starfive DESTINATION lib)
install (FILES libmctp.h libmctp-cmds.h libmctp-vdpci.h libmctp-smbus.h libmctp-astpcie.h libmctp-msgtypes.h libmctp-asti3c.h libmctp-log.h libmctp-starfive-i3c.h libmctp-starfive-pcie.h DESTINATION include)
