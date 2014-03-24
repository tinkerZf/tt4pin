/*
 * define Data-Flow-Trace relative variables and functions
 *
 *
 *
 */

#pragma once

#include "ttracer.h"
#include "dft_api.h"

typedef std::set<ADDRINT> Taint;
typedef std::map<ADDRINT, Taint> TaintMap;

#define MAX_NUM_CPUS 128
// each register use 4 byte, then 8 * 4 = 32
#define GPR_MEMS 32
#define BIT2BYTE(len)	((len) >> 3)
#define EFLAGS_DF(eflags)	((eflags & 0x0400))

#define MEM_LONG_LEN 32
#define MEM_WORD_LEN 16
#define MEM_BYTE_LEN 8



typedef struct _per_thread
{
	Taint reg_taint[GPR_MEMS + 4];//4 is for a virtual register
	bool taint_prop;

	_per_thread() : taint_prop(false) {}
} per_thread;

extern TaintMap taintMap;
extern per_thread thread_info[MAX_NUM_CPUS];

enum { OP_0 = 0, OP_1, OP_2, OP_3, OP_4};

void tagmap_setn(size_t addr, size_t num, Taint *t, size_t g = 1);// g --> grain
void tagmap_clrn(size_t addr, size_t num);

void PIN_FAST_ANALYSIS_CALL r_clrl(unsigned int reg, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r_clrw(unsigned int reg, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r_clrb(unsigned int reg, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r_clrl2(THREADID tid);
void PIN_FAST_ANALYSIS_CALL r_clrl4(THREADID tid);

void PIN_FAST_ANALYSIS_CALL r2r_binary_opl(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2r_binary_opw(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2r_binary_opb(unsigned int dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL m2r_binary_opl(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_binary_opw(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_binary_opb(unsigned int dst, ADDRINT src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL r2m_binary_opl(ADDRINT dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_binary_opw(ADDRINT dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_binary_opb(ADDRINT dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL tagmap_clrl(ADDRINT addr);
void PIN_FAST_ANALYSIS_CALL tagmap_clrw(ADDRINT addr);
void PIN_FAST_ANALYSIS_CALL tagmap_clrb(ADDRINT addr);

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb(unsigned int dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb(unsigned int dst, ADDRINT src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(ADDRINT dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(ADDRINT dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb(ADDRINT dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _cwde(THREADID tid);

void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplw(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opwb(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplb(unsigned int dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opwb(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movsx_m2r_oplw(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movsx_m2r_oplb(unsigned int dst, ADDRINT src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _movzx_r2r_oplw(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movzx_r2r_opwb(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movzx_r2r_oplb(unsigned int dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _movzx_m2r_opwb(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movzx_m2r_oplw(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _movzx_m2r_oplb(unsigned int dst, ADDRINT src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL m2r_ternary_opl(ADDRINT addr, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_ternary_opw(ADDRINT addr, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_ternary_opb(ADDRINT addr, THREADID tid);

void PIN_FAST_ANALYSIS_CALL r2r_ternary_opl(unsigned int reg, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2r_ternary_opw(unsigned int reg, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2r_ternary_opb(unsigned int reg, THREADID tid);


ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opl_fast(unsigned int dst_val, unsigned int src, unsigned int src_val, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opl_slow(unsigned int dst, unsigned int src, THREADID tid);
ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opw_fast(unsigned int dst_val, unsigned int src, unsigned int src_val, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opw_slow(unsigned int dst, unsigned int src, THREADID tid);

ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opl_fast(unsigned int dst_val, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opl_slow(ADDRINT dst, unsigned int src, THREADID tid);
ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opw_fast(unsigned short dst_val, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opw_slow(ADDRINT dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opw(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb(unsigned int dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opl(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opw(unsigned int dst, ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opb(unsigned int dst, ADDRINT src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opl(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opw(unsigned int dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb(unsigned int dst, unsigned int src, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opl(ADDRINT dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opw(ADDRINT dst, unsigned int src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opb(ADDRINT dst, unsigned int src, THREADID tid);

ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(ADDRINT dst, ADDRINT count, ADDRINT eflags, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn(ADDRINT dst, ADDRINT count, ADDRINT eflags, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln(ADDRINT dst, ADDRINT count, ADDRINT eflags, THREADID tid);

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src);

void PIN_FAST_ANALYSIS_CALL m2r_restore_opw(ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL m2r_restore_opl(ADDRINT src, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_save_opw(ADDRINT dst, THREADID tid);
void PIN_FAST_ANALYSIS_CALL r2m_save_opl(ADDRINT dst, THREADID tid);

void PIN_FAST_ANALYSIS_CALL _lea_r2r_opl(unsigned int dst, unsigned int base, unsigned int index, THREADID tid);
void PIN_FAST_ANALYSIS_CALL _lea_r2r_opw(unsigned int dst, unsigned int base, unsigned int index, THREADID tid);