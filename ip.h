#pragma once

#include "eunet.h"

uint32_t setIp(const std::string& ip);
void print_ip(uint32_t ip);
uint32_t getMyIp(const char* interface_name);