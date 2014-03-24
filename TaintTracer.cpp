#pragma once

#include "TaintTracer.h"

std::list<UINT64> addressTainted;
std::list<REG> regsTainted;

bool g_TaintFlag = true;

VOID TaintTracer(INS ins)
{
	//加入污点传播逻辑
	if (!g_TaintFlag) return;

	REG reg_dst, reg_src, reg_base, reg_indx;

	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

	if(ins_indx <= XED_ICLASS_INVALID || ins_indx >= XED_ICLASS_LAST) {
		OutFile << "pc=0x" << hex << INS_Address(ins) << ": unknown instruction" << endl;
		return;
	} else {
		OutFile << "pc=0x" << hex << INS_Address(ins) << ":" << INS_Disassemble(ins) << endl;
	}
	//return;
	if(INS_Address(ins) == 0x7c935206) {
		;
	}

	switch(ins_indx) {
		//
	case XED_ICLASS_ADC:
	case XED_ICLASS_ADD:
	case XED_ICLASS_AND:
	case XED_ICLASS_OR:
	case XED_ICLASS_XOR:
	case XED_ICLASS_SBB:
	case XED_ICLASS_SUB:
		if(INS_OperandIsImmediate(ins, OP_1)) {
			break;
		}
		if(INS_MemoryOperandCount(ins) == 0) {
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);
			//OutFile << reg_src << "-->" << reg_dst << endl;
			if(REG_is_gr32(reg_dst)) {
				switch(ins_indx) {
				case XED_ICLASS_XOR:
				case XED_ICLASS_SUB:
				case XED_ICLASS_SBB:
					if(reg_dst == reg_src) {
						//do_clear
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_UINT32, REG32_INDX(reg_dst),
							IARG_THREAD_ID,
							IARG_END);
						break;
					}
				default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG32_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
				}
			}
			else if(REG_is_gr16(reg_dst)) {
				//
				switch(ins_indx) {
				case XED_ICLASS_XOR:
				case XED_ICLASS_SUB:
				case XED_ICLASS_SBB:
					if(reg_dst == reg_src) {
						//do_clear
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_UINT32, REG16_INDX(reg_dst),
							IARG_THREAD_ID,
							IARG_END);
						break;
					}
				default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG16_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
				}
			} else {
				switch(ins_indx) {
				case XED_ICLASS_XOR:
				case XED_ICLASS_SUB:
				case XED_ICLASS_SBB:
					if(reg_dst == reg_src) {
						//do_clear
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb,
							IARG_FAST_ANALYSIS_CALL,
							IARG_UINT32, REG8_INDX(reg_dst),
							IARG_THREAD_ID,
							IARG_END);
						break;
					}
				default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
				}
			}
		} else if(INS_OperandIsMemory(ins, OP_1)) { //opt reg, mem
			//
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_binary_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_binary_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_binary_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);

		} else { //opt mem, reg
			//
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_binary_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_binary_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_binary_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		}
		break;
	case XED_ICLASS_BSF://line 2922
	case XED_ICLASS_BSR:
	case XED_ICLASS_MOV:
		//break;
		if(INS_OperandIsImmediate(ins, OP_1) ||
			(INS_OperandIsReg(ins, OP_1) && REG_is_seg(INS_OperandReg(ins, OP_1)))) {
			if(INS_OperandIsMemory(ins, OP_0)) {
				switch(INS_OperandWidth(ins, OP_0)) {
				case MEM_LONG_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					break;
				case MEM_WORD_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					break;
				case MEM_BYTE_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)tagmap_clrb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					break;
				default:
					return;
				}
			} else if(INS_OperandIsReg(ins, OP_0)) {
				//
				reg_dst = INS_OperandReg(ins, OP_0);
				if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG32_INDX(reg_dst),
						IARG_THREAD_ID,
						IARG_END);
				else if(REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG16_INDX(reg_dst),
						IARG_THREAD_ID,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG8_INDX(reg_dst),
						IARG_THREAD_ID,
						IARG_END);
			}

		} else if(INS_MemoryOperandCount(ins) == 0) {//both are registers
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		} else if(INS_OperandIsMemory(ins, OP_1)) {// reg <-- mem
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
		} else {// mem <-- reg
			//BUG
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else {
				//OutFile << "wtf here?" << endl;
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			}
		}
		break;
	case XED_ICLASS_CMOVB:// line 3244
	case XED_ICLASS_CMOVBE:
	case XED_ICLASS_CMOVL:
	case XED_ICLASS_CMOVLE:
	case XED_ICLASS_CMOVNB:
	case XED_ICLASS_CMOVNBE:
	case XED_ICLASS_CMOVNL:
	case XED_ICLASS_CMOVNLE:
	case XED_ICLASS_CMOVNO:
	case XED_ICLASS_CMOVNP:
	case XED_ICLASS_CMOVNS:
	case XED_ICLASS_CMOVNZ:
	case XED_ICLASS_CMOVO:
	case XED_ICLASS_CMOVP:
	case XED_ICLASS_CMOVS:
	case XED_ICLASS_CMOVZ:
		if(INS_MemoryOperandCount(ins) == 0) {
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		} else {
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);

		}
		break;
	case XED_ICLASS_CBW:// line 3340
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r2r_xfer_opb,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG8_INDX(REG_AH),
			IARG_UINT32, REG8_INDX(REG_AL),
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_CWD:// line 3360
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r2r_xfer_opw,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG16_INDX(REG_DX),
			IARG_UINT32, REG16_INDX(REG_AX),
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_CWDE:// line 3380
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)_cwde,
			IARG_FAST_ANALYSIS_CALL,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_CDQ:// line 3398
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r2r_xfer_opl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG32_INDX(REG_EDX),
			IARG_UINT32, REG32_INDX(REG_EAX),
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_MOVSX:// line 3417
		if(INS_MemoryOperandCount(ins) == 0) {// reg <-- reg
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);

			if(REG_is_gr16(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_r2r_opwb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			} else if(REG_is_gr16(reg_src)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_r2r_oplw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			} else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_r2r_oplb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			}
		} else {// reg <-- mem
			//
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_m2r_opwb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else if(INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_WORD_LEN))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_m2r_oplw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_m2r_oplb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
		}
		break;
	case XED_ICLASS_MOVZX:// line 3539
		if(INS_MemoryOperandCount(ins) == 0) {// reg <-- reg
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);

			if(REG_is_gr16(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movzx_r2r_opwb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			} else if(REG_is_gr16(reg_src)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movzx_r2r_oplw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			} else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movzx_r2r_oplb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			}
		} else {// reg <-- mem
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movzx_m2r_opwb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else if(INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_WORD_LEN))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movzx_m2r_oplw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movzx_m2r_oplb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
		}
		break;
	case XED_ICLASS_DIV:// line 3655
	case XED_ICLASS_IDIV:
	case XED_ICLASS_MUL:
		if(INS_OperandIsMemory(ins, OP_0))// mem included
			switch(INS_MemoryWriteSize(ins)) {
			case BIT2BYTE(MEM_LONG_LEN):
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_ternary_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
				break;
			case BIT2BYTE(MEM_WORD_LEN):
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_ternary_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
				break;
			case BIT2BYTE(MEM_BYTE_LEN):
			default:
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_ternary_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
				break;
			} // end inner switch
		else {// register included
			reg_src = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_ternary_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_ternary_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_ternary_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		}
		break;
	case XED_ICLASS_IMUL:// line 3768, and this is really horrible
		//break;
		if(INS_OperandIsImplicit(ins, OP_1)) {
			if(INS_OperandIsMemory(ins, OP_0))
				switch(INS_MemoryWriteSize(ins)) {
				case BIT2BYTE(MEM_LONG_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD_EA,
						IARG_THREAD_ID,
						IARG_END);
					break;
				case BIT2BYTE(MEM_WORD_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD_EA,
						IARG_THREAD_ID,
						IARG_END);
					break;
				case BIT2BYTE(MEM_BYTE_LEN):
				default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYREAD_EA,
						IARG_THREAD_ID,
						IARG_END);
					break;
			    }// end inner switch
			else {// register operand
				reg_src = INS_OperandReg(ins, OP_0);
				if(REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG32_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
				else if(REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG16_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG8_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);

			}
		} else {// two/three-operands form
			if(INS_OperandIsImmediate(ins, OP_1))
				break;
			if(INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG32_INDX(reg_dst),
						IARG_UINT32, REG32_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG16_INDX(reg_dst),
						IARG_UINT32, REG16_INDX(reg_src),
						IARG_THREAD_ID,
						IARG_END);
			} else {
				reg_dst = INS_OperandReg(ins, OP_0);
				if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG32_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_THREAD_ID,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_UINT32, REG16_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_THREAD_ID,
						IARG_END);
			}
		}
		break;
	case XED_ICLASS_SETB:// line 3937
	case XED_ICLASS_SETBE:
	case XED_ICLASS_SETL:
	case XED_ICLASS_SETLE:
	case XED_ICLASS_SETNB:
	case XED_ICLASS_SETNBE:
	case XED_ICLASS_SETNL:
	case XED_ICLASS_SETNLE:
	case XED_ICLASS_SETNO:
	case XED_ICLASS_SETNP:
	case XED_ICLASS_SETNS:
	case XED_ICLASS_SETNZ:
	case XED_ICLASS_SETO:
	case XED_ICLASS_SETP:
	case XED_ICLASS_SETS:
	case XED_ICLASS_SETZ:
		//break;
		if(INS_MemoryOperandCount(ins) == 0) {
			reg_dst = INS_OperandReg(ins, OP_0);
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG8_INDX(reg_dst),
				IARG_THREAD_ID,
				IARG_END);
		} else {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)tagmap_clrb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYREAD_EA,
				IARG_END);
		}
		break;
	case XED_ICLASS_STMXCSR:// line 3999
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)tagmap_clrl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_END);
		break;
	case XED_ICLASS_SMSW:// line 4011
	case XED_ICLASS_STR:
		reg_dst = INS_OperandReg(ins, OP_0);
		if(INS_MemoryOperandCount(ins) == 0) {
			if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_THREAD_ID,
					IARG_END);
		} else
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)tagmap_clrw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		break;
	case XED_ICLASS_LAR:// line 4060
		reg_dst = INS_OperandReg(ins, OP_0);
		if(REG_is_gr16(reg_dst))
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG16_INDX(reg_dst),
				IARG_THREAD_ID,
				IARG_END);
		else
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG32_INDX(reg_dst),
				IARG_THREAD_ID,
				IARG_END);
		break;
	case XED_ICLASS_RDPMC:// line 4088
	case XED_ICLASS_RDTSC:
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r_clrl2,
			IARG_FAST_ANALYSIS_CALL,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_CPUID:// line 4110
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r_clrl4,
			IARG_FAST_ANALYSIS_CALL,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_LAHF:// line 4125
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r_clrb,
			IARG_UINT32, REG8_INDX(REG_AH),
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_CMPXCHG:// line 4143
		if(INS_MemoryOperandCount(ins) == 0) {
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_dst)) {
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_r2r_opl_fast,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, REG_EAX,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_REG_VALUE, reg_dst,
					IARG_THREAD_ID,
					IARG_END);

				INS_InsertThenCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_r2r_opl_slow,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			} else if(REG_is_gr16(reg_dst)) {
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_r2r_opw_fast,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, REG_AX,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_REG_VALUE, reg_dst,
					IARG_THREAD_ID,
					IARG_END);

				INS_InsertThenCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_r2r_opw_slow,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			}
			
		} else {// memory operand
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_src)) {
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_m2r_opl_fast,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, REG_EAX,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);

				INS_InsertThenCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_r2m_opl_slow,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			} else if(REG_is_gr16(reg_src)) {
				INS_InsertIfCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_m2r_opw_fast,
					IARG_FAST_ANALYSIS_CALL,
					IARG_REG_VALUE, REG_AX,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);

				INS_InsertThenCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_cmpxchg_r2m_opw_slow,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			}
		}
		break;
	case XED_ICLASS_XCHG:// line 4260
		if(INS_MemoryOperandCount(ins) == 0) {
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);

			if(REG_is_gr32(reg_dst)) {
				INS_InsertCall(ins,// tmp <-- dst
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, GPR_MEMS,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_THREAD_ID,
					IARG_END);

				INS_InsertCall(ins,// dst <-- src
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);

				INS_InsertCall(ins,// src <-- tmp
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_UINT32, GPR_MEMS,
					IARG_THREAD_ID,
					IARG_END);
			} else if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_r2r_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_r2r_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		} else if(INS_OperandIsMemory(ins, OP_1)) {// end if no mem
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_dst)) 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_m2r_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_m2r_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_m2r_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
		} else {// end if reg <--> mem
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_src)) 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_m2r_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_m2r_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xchg_m2r_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
					
		} // end if mem <--> reg
		break;
	case XED_ICLASS_XADD:// line 4477
		if(INS_MemoryOperandCount(ins) == 0) {
			reg_dst = INS_OperandReg(ins, OP_0);
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xadd_r2r_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xadd_r2r_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xadd_r2r_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG8_INDX(reg_dst),
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		} else {// end no mem
			reg_src = INS_OperandReg(ins, OP_1);
			if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xadd_r2m_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xadd_r2m_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_xadd_r2m_opb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG8_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		}// end xadd mem, reg
		break;
	case XED_ICLASS_XLAT:// line 4642
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2r_xfer_opb,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG8_INDX(REG_AL),
			IARG_MEMORYREAD_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_LODSB:// line 4656
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2r_xfer_opb,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG8_INDX(REG_AL),
			IARG_MEMORYREAD_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_LODSW:// line 4670
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2r_xfer_opw,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG16_INDX(REG_AX),
			IARG_MEMORYREAD_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_LODSD:// line 4684
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2r_xfer_opl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG32_INDX(REG_EAX),
			IARG_MEMORYREAD_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_STOSB:// line 4705
		if(INS_RepPrefix(ins)) {
			INS_InsertIfPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)rep_predicate,
				IARG_FAST_ANALYSIS_CALL,
				IARG_FIRST_REP_ITERATION,
				IARG_END);
			INS_InsertThenPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_xfer_opbn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
				IARG_THREAD_ID,
				IARG_END);
		} else
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_xfer_opb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, REG8_INDX(REG_AL),
				IARG_THREAD_ID,
				IARG_END);

		break;
	case XED_ICLASS_STOSW:
		if(INS_RepPrefix(ins)) {
			INS_InsertIfPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)rep_predicate,
				IARG_FAST_ANALYSIS_CALL,
				IARG_FIRST_REP_ITERATION,
				IARG_END);
			INS_InsertThenPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_xfer_opwn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
				IARG_THREAD_ID,
				IARG_END);
		} else
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_xfer_opb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, REG16_INDX(REG_AX),
				IARG_THREAD_ID,
				IARG_END);

		break;
	case XED_ICLASS_STOSD:// line 4789
		if(INS_RepPrefix(ins)) {
			INS_InsertIfPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)rep_predicate,
				IARG_FAST_ANALYSIS_CALL,
				IARG_FIRST_REP_ITERATION,
				IARG_END);
			INS_InsertThenPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_xfer_opln,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, INS_RepCountRegister(ins),
				IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
				IARG_THREAD_ID,
				IARG_END);
		} else
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, REG32_INDX(REG_EAX),
				IARG_THREAD_ID,
				IARG_END);
		break;
	case XED_ICLASS_MOVSD:// line 4823
		INS_InsertPredicatedCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2m_xfer_opl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_MEMORYREAD_EA,
			IARG_END);
		break;
	case XED_ICLASS_MOVSW:// line 4836
		INS_InsertPredicatedCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2m_xfer_opw,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_MEMORYREAD_EA,
			IARG_END);
		break;
	case XED_ICLASS_MOVSB:// line 4849
		INS_InsertPredicatedCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2m_xfer_opb,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_MEMORYREAD_EA,
			IARG_END);
		break;
	case XED_ICLASS_SALC:// line 4862
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r_clrb,
			IARG_FAST_ANALYSIS_CALL,
			IARG_UINT32, REG8_INDX(REG_AL),
			IARG_THREAD_ID,
			IARG_END);
		break;
	//TODO: shifts are not handled!!!
	case XED_ICLASS_RCL:// line 4876    
	case XED_ICLASS_RCR:     
	case XED_ICLASS_ROL:       
	case XED_ICLASS_ROR:
	case XED_ICLASS_SHL:
	case XED_ICLASS_SAR:
	case XED_ICLASS_SHR:
	case XED_ICLASS_SHLD:
	case XED_ICLASS_SHRD:
		break;
	case XED_ICLASS_POP:// line 4896
		if(INS_OperandIsReg(ins, OP_0)) {
			reg_dst = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
		} else if(INS_OperandIsMemory(ins, OP_0)) {// end if reg
			if(INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYREAD_EA,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYREAD_EA,
					IARG_END);
		}//end if mem
		break;
	case XED_ICLASS_PUSH:// line 4953
		//break;
		if(INS_OperandIsReg(ins, OP_0)) {
			reg_src = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG32_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG16_INDX(reg_src),
					IARG_THREAD_ID,
					IARG_END);
		} else if(INS_OperandIsMemory(ins, OP_0)) {// end if reg
			if(INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYREAD_EA,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYREAD_EA,
					IARG_END);
		} else {// push imm or seg
			switch(INS_OperandWidth(ins, OP_0)) {
			case MEM_LONG_LEN:
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
				break;
			case MEM_WORD_LEN:
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
				break;
			case MEM_BYTE_LEN:
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrb,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
				break;
			default:
				break;
			}// end inner switch
		}
		break;
	case XED_ICLASS_POPA:// line 5059
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2r_restore_opw,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_POPAD:// line 5075
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)m2r_restore_opl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYREAD_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_PUSHA:// line 5091
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r2m_save_opw,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_PUSHAD:// line 5107
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)r2m_save_opl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_THREAD_ID,
			IARG_END);
		break;
	case XED_ICLASS_PUSHF:// line 5120
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)tagmap_clrw,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_END);
		break;
	case XED_ICLASS_PUSHFD:// line 5132
		INS_InsertCall(ins,
			IPOINT_BEFORE,
			(AFUNPTR)tagmap_clrl,
			IARG_FAST_ANALYSIS_CALL,
			IARG_MEMORYWRITE_EA,
			IARG_END);
		break;
	case XED_ICLASS_CALL_NEAR:// line 5144
		//break;
		if(INS_OperandIsImmediate(ins, OP_0)) {// relative target
			if(INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
		} else if(INS_OperandIsReg(ins, OP_0)) {// absolute target; reg
			reg_src = INS_OperandReg(ins, OP_0);
			if(REG_is_gr32(reg_src))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
		} else {// absolute target; mem
			if(INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			} else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)tagmap_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			}
		}
		break;
	case XED_ICLASS_LEAVE:// line 5218
		//break;
		reg_dst = INS_OperandReg(ins, OP_3);
		reg_src = INS_OperandReg(ins, OP_2);
		if(REG_is_gr32(reg_dst)) {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG32_INDX(reg_dst),
				IARG_UINT32, REG32_INDX(reg_src),
				IARG_THREAD_ID,
				IARG_END);
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG32_INDX(reg_src),
				IARG_MEMORYREAD_EA,
				IARG_THREAD_ID,
				IARG_END);
		} else {
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG16_INDX(reg_dst),
				IARG_UINT32, REG16_INDX(reg_src),
				IARG_THREAD_ID,
				IARG_END);
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_UINT32, REG16_INDX(reg_src),
				IARG_MEMORYREAD_EA,
				IARG_THREAD_ID,
				IARG_END);
		}
		break;
	case XED_ICLASS_LEA://5267
		//break;
		reg_base = INS_MemoryBaseReg(ins);
		reg_indx = INS_MemoryIndexReg(ins);
		reg_dst  = INS_OperandReg(ins, OP_0);

		if(reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_THREAD_ID,
					IARG_END);
		} // end no base or index register
		if(reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_base),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_base),
					IARG_THREAD_ID,
					IARG_END);
		} // end if base and no index
		if(reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
			if(REG_is_gr32(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_indx),
					IARG_THREAD_ID,
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_indx),
					IARG_THREAD_ID,
					IARG_END);
		}
		if(reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {
			if(REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_lea_r2r_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG32_INDX(reg_dst),
					IARG_UINT32, REG32_INDX(reg_base),
					IARG_UINT32, REG32_INDX(reg_indx),
					IARG_THREAD_ID,
					IARG_END);
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_lea_r2r_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_UINT32, REG16_INDX(reg_dst),
					IARG_UINT32, REG16_INDX(reg_base),
					IARG_UINT32, REG16_INDX(reg_indx),
					IARG_THREAD_ID,
					IARG_END);
		}// end base and index
		break;
	case XED_ICLASS_CMPXCHG8B:
	case XED_ICLASS_ENTER:
		break;
	default:
		break;
	}//end outer switch
	
}

//以下是privacyscope里实现的污点传播逻辑，供参考

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//  xed_iclass_enum_t opcode = (xed_iclass_enum_t) INS_Opcode(ins);
//  switch (opcode)
//  {
//  case XED_ICLASS_MOV:
//  case XED_ICLASS_MOVSB:
//  case XED_ICLASS_MOVSW:
//  case XED_ICLASS_MOVSD:
//  case XED_ICLASS_MOVZX:
//  case XED_ICLASS_MOVSX:
//	  {
//		  //Do MOXXX INS
//		  //MOVXX_TaintTracer(ins);
//		  return;
//	  }
//	  break;
//  case XED_ICLASS_XOR:
//  case XED_ICLASS_SUB:
//  case XED_ICLASS_SBB:
//	  {
//		  return;
//	  }
//	  break;
//  case XED_ICLASS_SYSCALL:
//  case XED_ICLASS_SYSENTER:
//  case XED_ICLASS_CMPXCHG:
//	  {
//		  return;
//	  }
//	  break;
//  default:
//	  break;
//  }
//
//
////++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// 
//  bool is_mem_read1, is_mem_read2, is_mem_write;
//  /* Step 1 - determine if we read or write any memory addresses */
//  is_mem_read1 = INS_IsMemoryRead(ins);
//  if (is_mem_read1)
//    is_mem_read2 = INS_HasMemoryRead2(ins);
//  else
//    is_mem_read2 = false;
//
//  is_mem_write = INS_IsMemoryWrite(ins);
//
//
//  /* Step 2 - Create a list of all registers tracked by DIFT that are
//   * read/written by the current instruction
//   */
//  UINT32 gr_read, gr_write, xt_read, xt_write;
//  gr_read = gr_write = xt_read = xt_write = 0;
//  for (UINT32 i=0; i < INS_MaxNumRRegs(ins); i++)
//  {
//    reg =  INS_RegR(ins, i);
//
//    if (!REG_is_dift(reg)) continue;
//
//    if (REG_is_gr(reg))
//	{
//      gr_read |= 1 << (reg - REG_GR_BASE);
//	}
//    else if (REG_is_gr8(reg) || REG_is_gr16(reg))
//    {
//      gr_read |= 1 << (reg - REG_AL + NR_REG(REG_GR));
//    }
//  }
//
//  for (UINT32 i=0; i < INS_MaxNumWRegs(ins); i++)
//  {
//    reg = INS_RegW(ins,i);
//
//    if (!REG_is_dift(reg)) continue;
//
//    if (REG_is_gr(reg))
//	{
//      gr_write |= 1 << (reg - REG_GR_BASE);
//	}
//    else if (REG_is_gr8(reg) || REG_is_gr16(reg))
//    {
//      gr_write |= 1 << (reg - REG_AL + NR_REG(REG_GR));
//    }
//  }
//
//  if (INS_RepPrefix(ins)) 
//  {
//    gr_read &= ~(1 << (REG_ECX -REG_GR_BASE )); // ecx is used as counter in rep instructions
//    gr_read &= ~(1 << (REG_EDI -REG_GR_BASE )); // edi is used as counter in rep instructions
//    gr_read &= ~(1 << (REG_ESI -REG_GR_BASE )); // esi is used as counter in rep instructions
//
//    gr_write &= ~(1 << (REG_ECX -REG_GR_BASE )); // ecx is used as counter in rep instructions
//    gr_write &= ~(1 << (REG_EDI -REG_GR_BASE )); // edi is used as counter in rep instructions
//    gr_write &= ~(1 << (REG_ESI -REG_GR_BASE )); // esi is used as counter in rep instructions
//  }
//
//  if (!gr_write  && !is_mem_write) 
//    return; 
//
//  /* Step 4 - Prepare arguments for call to DoProp
//   * This assumes an instruction does not read/write to its own code,
//   * i.e. does not write to the memory address indicated by the PC.
//   */
//  // no mem read or write, mmx read and write are false, no mem read or write, just write to one general register
//  if (!MaxNumMaskReg(xt_read) && !MaxNumMaskReg(xt_write) && !is_mem_read1 &&
//    !is_mem_write && MaxNumMaskReg(gr_write) == 1
//    && gr_read < (1 << NR_REG(REG_GR)) 
//    && gr_write < (1 << NR_REG(REG_GR)))
//  {
//    if (MaxNumMaskReg(gr_read) == 0)
//    {
//      IFCOND(ins);
//      INS_InsertThenCall(ins,IPOINT_BEFORE, 
//        (AFUNPTR) RegisterUntaint,IARG_FAST_ANALYSIS_CALL,
//        IARG_UINT32, iaddr,
//        IARG_UINT32, MaskReg(gr_write,0),
//        IARG_THREAD_ID,
//        IARG_END);
//    }
//    else if (MaxNumMaskReg(gr_read) == 1)
//    {
//      assert (MaskReg(gr_read,0) < NR_REG(REG_GR));
//      assert (MaskReg(gr_write,0) < NR_REG(REG_GR));
//                    
//      IFCOND(ins);   
//      INS_InsertThenCall(ins,IPOINT_BEFORE, 
//        (AFUNPTR) DoPropRegR1,IARG_FAST_ANALYSIS_CALL,
//        IARG_UINT32, iaddr,
//        IARG_UINT32, MaskReg(gr_read,0) + REG_GR_BASE,
//        IARG_UINT32, MaskReg(gr_write,0) + REG_GR_BASE,
//        IARG_THREAD_ID,
//        IARG_END);
//      return;
//    } 
//    else if (MaxNumMaskReg(gr_read) == 2)
//    {
//      assert (MaskReg(gr_read,0) < NR_REG(REG_GR));
//      assert (MaskReg(gr_write,0) < NR_REG(REG_GR));
//      assert (MaskReg(gr_read,1) < NR_REG(REG_GR));
//      IFCOND(ins);
//      INS_InsertThenCall(ins,IPOINT_BEFORE, 
//        (AFUNPTR) DoPropRegR2,IARG_FAST_ANALYSIS_CALL,
//        IARG_UINT32, iaddr,
//        IARG_UINT32, MaskReg(gr_read,0) + REG_GR_BASE,
//        IARG_UINT32, MaskReg(gr_read,1) + REG_GR_BASE,
//        IARG_UINT32, MaskReg(gr_write,0) + REG_GR_BASE,
//        IARG_THREAD_ID,
//        IARG_END);
//      return;
//    }
//  }
//  // there is mem read or write, but no xt reads or xt writes
//  if (!MaxNumMaskReg(xt_read) && !MaxNumMaskReg(xt_write))
//  {
//    IFCOND(ins);
//    INS_InsertThenCall(ins,IPOINT_BEFORE, 
//      (AFUNPTR) DoPropNoExtReg,IARG_FAST_ANALYSIS_CALL,
//      IARG_UINT32, iaddr,
//      IARG_UINT32, gr_read, 
//      IARG_UINT32, gr_write, 
//      is_mem_read1 ? IARG_MEMORYREAD_EA : IARG_INST_PTR,
//      is_mem_read2 ? IARG_MEMORYREAD2_EA : IARG_INST_PTR,
//      is_mem_read1 ? IARG_MEMORYREAD_SIZE : IARG_INST_PTR,
//      is_mem_write ? IARG_MEMORYWRITE_EA : IARG_INST_PTR,
//      is_mem_write ? IARG_MEMORYWRITE_SIZE : IARG_INST_PTR,
//      IARG_THREAD_ID,
//      IARG_END);
//    return;
//  }
//  
//  IFCOND(ins);
//  INS_InsertThenCall(ins,IPOINT_BEFORE, 
//    (AFUNPTR) DoProp,
//    IARG_FAST_ANALYSIS_CALL,
//    IARG_UINT32, iaddr,
//    IARG_UINT32, gr_read, IARG_UINT32, xt_read,
//    IARG_UINT32, gr_write, IARG_UINT32, xt_write,
//    is_mem_read1 ? IARG_MEMORYREAD_EA : IARG_INST_PTR,
//    is_mem_read2 ? IARG_MEMORYREAD2_EA : IARG_INST_PTR,
//    is_mem_read1 ? IARG_MEMORYREAD_SIZE : IARG_INST_PTR,
//    is_mem_write ? IARG_MEMORYWRITE_EA : IARG_INST_PTR,
//    is_mem_write ? IARG_MEMORYWRITE_SIZE : IARG_INST_PTR,
//    IARG_THREAD_ID,
//    IARG_END);
//}