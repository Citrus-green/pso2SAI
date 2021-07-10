#pragma once
#include <cstdint>

struct StUnknown {
	uint32_t count[0x14];
	uint64_t address[0x14];
};