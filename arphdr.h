# pragma once

#include "eunet.h"

#pragma pack(push, 1)
struct ArpHdr {
    uint16_t hrd_;
    uint16_t pro_;
    uint8_t hlen_;
    uint8_t plen_;
    uint16_t op_;
    uint8_t smac_[6];    
    uint32_t sip_;
    uint8_t dmac_[6];
    uint32_t dip_;

    // network link protocol
    enum: uint16_t {
        ETHERNET = 1
    };

    // opcode
    enum: uint16_t {
        REQUEST = 1,
        REPLY = 2
    };
};
#pragma pack(pop)