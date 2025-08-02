#pragma once

#include "eunet.h"

uint8_t* setMac(const string& mac);
void printMac(const uint8_t* mac);
bool getMyMac(const char* interface_name, uint8_t* mac_addr);