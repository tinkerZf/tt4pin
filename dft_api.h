/*
 * define translation functions
 *
 *
 *
 */

#pragma once

#include "ttracer.h"


#define R32_ALIGN 12

/* we map registers to memory address
 * it's tricky, but it does work
 *
 * eax 0x40
 * ecx 0x44
 * edx 0x48
 * ebx 0x4c
 * esp 0x50
 * ebp 0x54
 * esi 0x58
 * edi 0x5c
 *
 */
enum {
	REG_ADDR_EDI = 0x00,
	REG_ADDR_ESI = 0x04,
	REG_ADDR_EBP = 0x08,
	REG_ADDR_ESP = 0x0c,

	REG_ADDR_EBX = 0x10,
	REG_ADDR_EDX = 0x14,
	REG_ADDR_ECX = 0x18,
	REG_ADDR_EAX = 0x1c,
	REG_ADDR_END = 0x20
};

size_t REG32_INDX(REG reg);
size_t REG16_INDX(REG reg);
size_t REG8_INDX(REG reg);

