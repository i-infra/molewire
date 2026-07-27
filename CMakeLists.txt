# pico-wg-dongle: USB WireGuard adapter for the Raspberry Pi Pico 2 W.

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()

# RP2350 only: the WireGuard crypto wants the M33, key handling wants the TRNG.
set(PICO_BOARD pico2_w CACHE STRING "Board type")

include(pico_sdk_import.cmake)

project(pico-wg-dongle C CXX ASM)

pico_sdk_init()

add_executable(pico-wg-dongle
    src/main.c
    src/config.c
    src/config_proto.c
    src/serial_console.c
    src/wifi_scan.c
    src/debug_console.c
    src/usb_net.c
    src/dhcp_server.c
    src/wg.c
    src/usb_descriptors.c
    wireguard/wireguard.c
    wireguard/wireguardif.c
    wireguard/crypto.c
    wireguard/crypto/refc/blake2s.c
    wireguard/crypto/refc/chacha20.c
    wireguard/crypto/refc/chacha20poly1305.c
    wireguard/crypto/refc/poly1305-donna.c
    wireguard/crypto/refc/x25519.c
)

# Firmware version from the git tag (see pico-usb-wifi).
if(NOT DEFINED FW_VERSION)
  execute_process(
    COMMAND git describe --tags --dirty --always
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    OUTPUT_VARIABLE FW_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
endif()
if(NOT FW_VERSION)
  set(FW_VERSION "0.0.0-dev")
endif()
message(STATUS "Firmware version: ${FW_VERSION}")
target_compile_definitions(pico-wg-dongle PRIVATE FW_VERSION="${FW_VERSION}")

pico_set_program_name(pico-wg-dongle "pico-wg-dongle")
pico_set_program_version(pico-wg-dongle "${FW_VERSION}")

pico_enable_stdio_uart(pico-wg-dongle 1)
pico_enable_stdio_usb(pico-wg-dongle 0)

target_link_libraries(pico-wg-dongle
    pico_stdlib
    tinyusb_device
    pico_cyw43_arch_lwip_threadsafe_background   # Wi-Fi serviced in background IRQ so USB (tud_task) never starves
    pico_unique_id
    pico_rand           # TRNG-backed randomness for WireGuard session keys
    pico_flash          # flash_safe_execute() for config + boot counter
    hardware_flash
    hardware_watchdog
)

target_include_directories(pico-wg-dongle PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src       # project headers, tusb_config.h, lwipopts.h, lwip_hooks.h
    ${CMAKE_CURRENT_LIST_DIR}/wireguard # wireguardif.h, wireguard.h, crypto
)

pico_add_extra_outputs(pico-wg-dongle)
