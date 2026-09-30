# PSU-Link: link protocol between a charging controller and its power node
# (UART / ESP-NOW). Portable C99, zero platform dependencies.
#
# ESP-IDF:    used as a component (idf_component_register). The core is still pure
#             C99; port/esp_idf/ adds the mbedTLS implementation of psu_crypto_t
#             used by pairing and link authentication.
# STM32/PC:   add_library / target_include_directories; supply your own psu_crypto_t

if(ESP_PLATFORM)
    idf_component_register(
        SRCS "psu_link.c" "psu_pair.c" "psu_sess.c" "port/esp_idf/psu_crypto_mbedtls.c"
        INCLUDE_DIRS "include"
        PRIV_REQUIRES mbedtls esp_hw_support
    )
else()
    cmake_minimum_required(VERSION 3.16)
    project(psu_link C)
    add_library(psu_link STATIC psu_link.c psu_pair.c psu_sess.c)
    target_include_directories(psu_link PUBLIC include)
    target_compile_features(psu_link PUBLIC c_std_99)
endif()
