/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Ha Thach (tinyusb.org)
 * Copyright (c) 2024 Matthew Bennett
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <lwip/opt.h>

// Pico USB device roothub port number
#ifndef PICO_TUD_RHPORT
#define PICO_TUD_RHPORT 0
#endif

//--------------------------------------------------------------------
// Common Configuration
//--------------------------------------------------------------------

// defined by compiler flags for flexibility
#ifndef CFG_TUSB_MCU
#error CFG_TUSB_MCU must be defined
#endif

#ifndef CFG_TUSB_OS
#define CFG_TUSB_OS OPT_OS_NONE
#endif

#ifndef CFG_TUSB_DEBUG
#define CFG_TUSB_DEBUG 0
#endif

// Enable Device stack
#define CFG_TUD_ENABLED 1

// Default is max speed that hardware controller could support with on-chip PHY
#define CFG_TUD_MAX_SPEED OPT_MODE_DEFAULT_SPEED

/* USB DMA on some MCUs can only access a specific SRAM region with restriction on alignment.
 * Tinyusb use follows macros to declare transferring memory so that they can be put
 * into those specific section.
 * e.g
 * - CFG_TUSB_MEM SECTION : __attribute__ (( section(".usb_ram") ))
 * - CFG_TUSB_MEM_ALIGN   : __attribute__ ((aligned(4)))
 */
#ifndef CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_SECTION
#endif

#ifndef CFG_TUSB_MEM_ALIGN
#define CFG_TUSB_MEM_ALIGN __attribute__((aligned(4)))
#endif

//--------------------------------------------------------------------
// NCM CLASS CONFIGURATION, SEE "ncm.h" FOR PERFORMANCE TUNING
//--------------------------------------------------------------------

// Must be >> MTU
// Can be set to 2048 without impact
#define CFG_TUD_NCM_IN_NTB_MAX_SIZE (2 * TCP_MSS + 100)

// Must be >> MTU
// Can be set to smaller values if wNtbOutMaxDatagrams==1
#define CFG_TUD_NCM_OUT_NTB_MAX_SIZE (2 * TCP_MSS + 100)

// Number of NCM transfer blocks for reception side
#ifndef CFG_TUD_NCM_OUT_NTB_N
#define CFG_TUD_NCM_OUT_NTB_N 1
#endif

// Number of NCM transfer blocks for transmission side. 2 enables double
// buffering: the device builds the next batch (device->host, the heavy bridge
// direction) while the current one is in flight, instead of stalling the USB-TX
// ring until each block drains.
#ifndef CFG_TUD_NCM_IN_NTB_N
#define CFG_TUD_NCM_IN_NTB_N 2
#endif

//--------------------------------------------------------------------
// DEVICE CONFIGURATION
//--------------------------------------------------------------------

#ifndef CFG_TUD_ENDPOINT0_SIZE
#define CFG_TUD_ENDPOINT0_SIZE 64
#endif

//------------- CLASS -------------//

// TinyUSB's network class has two mutually exclusive drivers, ECM/RNDIS and
// NCM. This firmware uses NCM: it is the more efficient framing (multiple
// datagrams batched per USB transfer) and is driven in-box by Windows 10+
// (via the MS OS 2.0 WINNCM binding in usb_descriptors.c), macOS, and Linux.
#define CFG_TUD_ECM_RNDIS 0
#define CFG_TUD_NCM 1

// Three CDC-ACM serial functions alongside the network class: a management
// console (instance 0, serial_console.c), a debug-output console (instance 1,
// debug_console.c), and a raw serial<->TCP bridge (instance 2,
// serial_bridge.c) whose byte stream is exposed on TCP :2323 at the device's
// WireGuard address. The consoles are reachable the instant USB enumerates --
// before Wi-Fi is up -- and carry no IP, so the device can be provisioned and
// observed out of band.
#define CFG_TUD_CDC 3
#define CFG_TUD_CDC_RX_BUFSIZE 256

// One vendor-class (WebUSB) interface. Its purpose is to exist unclaimed: on
// macOS every other interface here is grabbed by a kernel driver (NCM, 2x
// ACM), and Chromium cannot open a device it holds no unclaimed interface on
// -- which blocks the GET_URL fetch behind the WebUSB landing-page prompt.
// The bulk endpoints carry no protocol today.
#define CFG_TUD_VENDOR 1
#define CFG_TUD_VENDOR_RX_BUFSIZE 64
#define CFG_TUD_VENDOR_TX_BUFSIZE 64
// TX must hold the largest single console reply without yielding to tud_task,
// since the console emits a reply in one main-loop tick: the worst case is a
// full scan list (WIFI_SCAN_MAX networks, ~64 B/line) plus its prompt. Too small
// and the tail -- including the prompt -- is silently dropped, which looks like a
// hung console.
#define CFG_TUD_CDC_TX_BUFSIZE 2048

#ifdef __cplusplus
}
#endif

#endif /* _TUSB_CONFIG_H_ */
