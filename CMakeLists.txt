# PSU-Link: link protocol between a charging controller and its power node
# (UART / ESP-NOW). Portable C99, zero platform dependencies.
#
# ESP-IDF:    used as a component (idf_component_register)
# STM32/PC:   add_library / target_include_directories

if(ESP_PLATFORM)
    idf_component_register(
        SRCS "psu_link.c"
        INCLUDE_DIRS "include"
        # No REQUIRES: pure C99, zero platform/OS dependencies
    )
else()
    cmake_minimum_required(VERSION 3.16)
    project(psu_link C)
    add_library(psu_link STATIC psu_link.c)
    target_include_directories(psu_link PUBLIC include)
    target_compile_features(psu_link PUBLIC c_std_99)
endif()
