# pragma once

#include "eunet.h"

struct EthHdr {
    uint8_t dmac_[6];
    uint8_t smac_[6];
    uint16_t type_;

    // ethernet types
    enum: uint16_t {
      IP4 = 0x0800,
      ARP = 0x0806,
      IP6 = 0x86DD
	};
};