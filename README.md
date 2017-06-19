# Native Blynk client for ESP-IDF (Espressif ESP32 mainline SDK)
Control your ESP-IDF project using [Blynk](https://www.blynk.cc) platform

## Installation
This component is intended to be used as ESP-IDF project subcomponent. Just clone it into `components` subdirectory inside your project source tree.

## LwIP loopback
This implementation relies on LwIP loopback feature. This feature is disabled in ESP-IDF 2.0. To enable it: 
 - Add following lines to your project Makefile:
    ```Makefile
    CFLAGS += -DLWIP_NETIF_LOOPBACK=1
    CFLAGS += -DLWIP_LOOPBACK_MAX_PBUFS=8
    ```
- Rebuild your project as well as ESP-IDF:
    ```
    make clean && make all
    ```

## How to use
See an [example application](https://github.com/e-asphyx/esp-blynk-app)

Happy blynking!