#include "dft_api.h"

size_t REG32_INDX(REG reg)
{
	switch(reg) {
	case REG_EAX:
		return REG_ADDR_EAX;
		break;
	case REG_ECX:
		return REG_ADDR_ECX;
		break;
	case REG_EDX:
		return REG_ADDR_EDX;
		break;
	case REG_EBX:
		return REG_ADDR_EBX;
		break;
	case REG_ESP:
		return REG_ADDR_ESP;
		break;
	case REG_EBP:
		return REG_ADDR_EBP;
		break;
	case REG_ESI:
		return REG_ADDR_ESI;
		break;
	case REG_EDI:
		return REG_ADDR_EDI;
		break;
	default:
		return REG_ADDR_END;
	}
}

size_t REG16_INDX(REG reg)
{
	switch(reg) {
	case REG_AX:
		return REG_ADDR_EAX;
		break;
	case REG_CX:
		return REG_ADDR_ECX;
		break;
	case REG_DX:
		return REG_ADDR_EDX;
		break;
	case REG_BX:
		return REG_ADDR_EBX;
		break;
	case REG_SP:
		return REG_ADDR_ESP;
		break;
	case REG_BP:
		return REG_ADDR_EBP;
		break;
	case REG_SI:
		return REG_ADDR_ESI;
		break;
	case REG_DI:
		return REG_ADDR_EDI;
		break;
	default:
		return REG_ADDR_END;
	}
}

size_t REG8_INDX(REG reg)
{
	switch(reg) {
	case REG_AL:
		return REG_ADDR_EAX;
		break;
	case REG_AH:
		return REG_ADDR_EAX + 1;
		break;
	case REG_CL:
		return REG_ADDR_ECX;
		break;
	case REG_CH:
		return REG_ADDR_ECX + 1;
		break;
	case REG_DL:
		return REG_ADDR_EDX;
		break;
	case REG_DH:
		return REG_ADDR_EDX + 1;
		break;
	case REG_BL:
		return REG_ADDR_EBX;
		break;
	case REG_BH:
		return REG_ADDR_EBX + 1;
		break;
	default:
		return REG_ADDR_END;
	}
}
