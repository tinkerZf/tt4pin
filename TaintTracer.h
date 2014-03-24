#pragma once
#include "ttracer.h"
#include "dft_core.h"

extern ofstream OutFile;
extern std::list<UINT64> addressTainted;
extern std::list<REG> regsTainted;

extern bool setb;

void TaintTracer(INS ins);


VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp);

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp);

VOID SpreadReg(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w);

VOID FollowData(UINT64 insAddr, std::string insDis, REG reg);