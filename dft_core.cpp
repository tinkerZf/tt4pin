#include "dft_core.h"

void tagmap_setn(size_t addr, size_t num, Taint *t, size_t g)
{
	size_t m = g - 1;// m --> mask
	for(size_t i = 0; i < num; ++i) {
		taintMap[addr + i] = *(t + ( i & m));
	}
}

void tagmap_clrn(size_t addr, size_t num)
{
	for(size_t i = 0; i < num; ++i) {
		taintMap.erase(addr + i);
	}
}

// clear a register
void PIN_FAST_ANALYSIS_CALL
r_clrl(unsigned int reg, THREADID tid)
{
	for(int i = 0; i < 4; ++i) {
		r_clrb(reg + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r_clrw(unsigned int reg, THREADID tid)
{
	for(int i = 0; i < 2; ++i) {
		r_clrb(reg + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r_clrb(unsigned int reg, THREADID tid)
{
	thread_info[tid].reg_taint[reg].clear();
}

void PIN_FAST_ANALYSIS_CALL
r_clrl2(THREADID tid)// clear eax and edx
{
	r_clrl(REG32_INDX(REG_EAX), tid);
	r_clrl(REG32_INDX(REG_EDX), tid);
}

void PIN_FAST_ANALYSIS_CALL
r_clrl4(THREADID tid)// clear eax, ecx, edx and ebx
{
	r_clrl(REG32_INDX(REG_EAX), tid);
	r_clrl(REG32_INDX(REG_ECX), tid);
	r_clrl(REG32_INDX(REG_EDX), tid);
	r_clrl(REG32_INDX(REG_EBX), tid);
}

/*
 *
 * here, we ignore carry bit like, just for simplicity
 * 0x00FF + 0x00FF
 * MSB in fact is influenced by LSB
 *
 */
// add taint, reg <-- reg
void PIN_FAST_ANALYSIS_CALL
r2r_binary_opl(unsigned int dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 4; ++i) {
		r2r_binary_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2r_binary_opw(unsigned int dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 2; ++i) {
		r2r_binary_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst].insert(thread_info[tid].reg_taint[src].begin(), thread_info[tid].reg_taint[src].end());
}

// add taint, reg <- mem
void PIN_FAST_ANALYSIS_CALL
m2r_binary_opl(unsigned int dst, ADDRINT src, THREADID tid)
{
	for(int i = 0; i < 4; ++i) {
		m2r_binary_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_binary_opw(unsigned int dst, ADDRINT src, THREADID tid)
{
	//
	for(int i = 0; i < 2; ++i) {
		m2r_binary_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb(unsigned int dst, ADDRINT src, THREADID tid)
{
	//
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst].insert(it->second.begin(), it->second.end());
	}
}

// add taint, mem <-- reg
void PIN_FAST_ANALYSIS_CALL
r2m_binary_opl(ADDRINT dst, unsigned int src, THREADID tid)
{
	//
	for(int i = 0; i < 4; ++i)
	{
		r2m_binary_opb(dst, src, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_binary_opw(ADDRINT dst, unsigned int src, THREADID tid)
{
	//
	for(int i = 0; i < 2; ++i)
	{
		r2m_binary_opb(dst, src, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb(ADDRINT dst, unsigned int src, THREADID tid)
{
	//
	Taint &t = thread_info[tid].reg_taint[src];
	if(t.size() != 0) {
		taintMap[dst].insert(t.begin(), t.end());
	} else {
		if(taintMap.find(dst) != taintMap.end())
			taintMap.erase(dst);
	}
}

// clear memory address taint
void PIN_FAST_ANALYSIS_CALL
tagmap_clrl(ADDRINT addr)
{
	for(int i = 0; i < 4; ++i) {
		tagmap_clrb(addr + i);
	}
}

void PIN_FAST_ANALYSIS_CALL
tagmap_clrw(ADDRINT addr)
{
	for(int i = 0; i < 2; ++i) {
		tagmap_clrb(addr + i);
	}
}

void PIN_FAST_ANALYSIS_CALL
tagmap_clrb(ADDRINT addr)
{
	taintMap.erase(addr);
}

// move taint, reg <-- reg
void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl(unsigned int dst, unsigned int src, THREADID tid)
{
	//
	OutFile << "Enter r2r_xfer_opl: " << dst << " <-- " << src << endl;
	for(int i = 0; i < 4; ++i)
	{
		r2r_xfer_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw(unsigned int dst, unsigned int src, THREADID tid)
{
	//
	for(int i = 0; i < 2; ++i)
	{
		r2r_xfer_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb(unsigned int dst, unsigned int src, THREADID tid)
{
	//
	//OutFile << "Enter r2r_xfer_opb: " << tid << endl;
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
}

// move taint, reg <-- mem
void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opl(unsigned int dst, ADDRINT src, THREADID tid)
{
	//
	for(int i = 0; i < 4; ++i)
	{
		m2r_xfer_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opw(unsigned int dst, ADDRINT src, THREADID tid)
{
	//
	for(int i = 0; i < 2; ++i)
	{
		m2r_xfer_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb(unsigned int dst, ADDRINT src, THREADID tid)
{
	//
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
	}
}


// move taint, mem <-- reg
void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl(ADDRINT dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 4; ++i)
	{
		r2m_xfer_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw(ADDRINT dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 2; ++i)
	{
		r2m_xfer_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb(ADDRINT dst, unsigned int src, THREADID tid)
{
	Taint &t = thread_info[tid].reg_taint[src];
	if(t.size() != 0) {
		taintMap[dst] = t;
	} else {
		if(taintMap.find(dst) != taintMap.end())
			taintMap.erase(dst);
	}
}

// cwde, use signed bit of ax to extend eax
// this only makes a litte difference
void PIN_FAST_ANALYSIS_CALL
_cwde(THREADID tid)
{
	//
	unsigned int eax = REG32_INDX(REG_EAX);
	// 3 2 1 0
	thread_info[tid].reg_taint[eax + 2] = thread_info[tid].reg_taint[eax + 1];
	thread_info[tid].reg_taint[eax + 3] = thread_info[tid].reg_taint[eax + 1];
}

// movsx, use singed bit of src to extend dst
// reg <-- reg
void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplw(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 1] = thread_info[tid].reg_taint[src + 1];
	thread_info[tid].reg_taint[dst + 2] = thread_info[tid].reg_taint[src + 1];
	thread_info[tid].reg_taint[dst + 3] = thread_info[tid].reg_taint[src + 1];
}

void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 1] = thread_info[tid].reg_taint[src];
}

void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 1] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 2] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 3] = thread_info[tid].reg_taint[src];
}

// movsx, use singed bit of src to extend dst
// reg <-- mem
void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opwb(unsigned int dst, ADDRINT src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
		thread_info[tid].reg_taint[dst + 1] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
		thread_info[tid].reg_taint[dst + 1].clear();
	}
}

void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplw(unsigned int dst, ADDRINT src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
	}

	it = taintMap.find(src + 1);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst + 1] = it->second;
		thread_info[tid].reg_taint[dst + 2] = it->second;
		thread_info[tid].reg_taint[dst + 3] = it->second;
	} else {
		thread_info[tid].reg_taint[dst + 1].clear();
		thread_info[tid].reg_taint[dst + 2].clear();
		thread_info[tid].reg_taint[dst + 3].clear();
	}
}

void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplb(unsigned int dst, ADDRINT src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
		thread_info[tid].reg_taint[dst + 1] = it->second;
		thread_info[tid].reg_taint[dst + 2] = it->second;
		thread_info[tid].reg_taint[dst + 3] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
		thread_info[tid].reg_taint[dst + 1].clear();
		thread_info[tid].reg_taint[dst + 2].clear();
		thread_info[tid].reg_taint[dst + 3].clear();
	}
}

// movzx, use zero to extend dst
// reg <-- reg
void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplw(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 1] = thread_info[tid].reg_taint[src + 1];
	thread_info[tid].reg_taint[dst + 2].clear();
	thread_info[tid].reg_taint[dst + 3].clear();
}

void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 1].clear();
}

void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb(unsigned int dst, unsigned int src, THREADID tid)
{
	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[dst + 1].clear();
	thread_info[tid].reg_taint[dst + 2].clear();
	thread_info[tid].reg_taint[dst + 3].clear();
}

// movzx, use zero to extend dst
// reg <-- mem
void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opwb(unsigned int dst, ADDRINT src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
	}
	thread_info[tid].reg_taint[dst + 1].clear();
}

void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplw(unsigned int dst, ADDRINT src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
	}

	it = taintMap.find(src + 1);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst + 1] = it->second;
	} else {
		thread_info[tid].reg_taint[dst + 1].clear();
	}
	thread_info[tid].reg_taint[dst + 2].clear();
	thread_info[tid].reg_taint[dst + 3].clear();
}

void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplb(unsigned int dst, ADDRINT src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
	}
	thread_info[tid].reg_taint[dst + 1].clear();
	thread_info[tid].reg_taint[dst + 2].clear();
	thread_info[tid].reg_taint[dst + 3].clear();
}

// mul/div, the third is mem
/*
 * i admit that this is a bit of weird, but whatever
 *
 */
void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opl(ADDRINT addr, THREADID tid)// affecet eax and edx
{	
	unsigned int eax = REG32_INDX(REG_EAX);
	unsigned int edx = REG32_INDX(REG_EDX);

	TaintMap::iterator it = taintMap.find(addr);
	if(it != taintMap.end()) {

		Taint::iterator tb = it->second.begin();
		Taint::iterator te = it->second.end();

		for(int i = 0; i < 4; ++i) {
			thread_info[tid].reg_taint[eax + i].insert(tb ,te);
			thread_info[tid].reg_taint[edx + i].insert(tb ,te);
		}
	} else {
		for(int i = 0; i < 4; ++i) {
			thread_info[tid].reg_taint[eax + i].clear();
			thread_info[tid].reg_taint[edx + i].clear();
		}
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opw(ADDRINT addr, THREADID tid)// affect ax and dx
{
	unsigned int ax = REG16_INDX(REG_AX);
	unsigned int dx = REG16_INDX(REG_DX);

	TaintMap::iterator it = taintMap.find(addr);
	if(it != taintMap.end()) {
		Taint::iterator tb = it->second.begin();
		Taint::iterator te = it->second.end();

		thread_info[tid].reg_taint[ax].insert(tb, te);
		thread_info[tid].reg_taint[ax + 1].insert(tb, te);

		thread_info[tid].reg_taint[dx].insert(tb, te);
		thread_info[tid].reg_taint[dx + 1].insert(tb, te);
	} else {
		thread_info[tid].reg_taint[ax].clear();
		thread_info[tid].reg_taint[ax + 1].clear();

		thread_info[tid].reg_taint[dx].clear();
		thread_info[tid].reg_taint[dx + 1].clear();
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opb(ADDRINT addr, THREADID tid)// affect ax
{
	unsigned int ax = REG16_INDX(REG_AX);

	TaintMap::iterator it = taintMap.find(addr);
	if(it != taintMap.end()) {
		Taint::iterator tb = it->second.begin();
		Taint::iterator te = it->second.end();

		thread_info[tid].reg_taint[ax].insert(tb, te);
		thread_info[tid].reg_taint[ax + 1].insert(tb, te);
	} else {
		thread_info[tid].reg_taint[ax].clear();
		thread_info[tid].reg_taint[ax + 1].clear();
	}
}

// mul/div, the third is mem
/*
 * i admit that this is a bit of weird, but whatever
 *
 */

void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opl(unsigned int reg, THREADID tid)// affect eax and edx
{
	unsigned int eax = REG32_INDX(REG_EAX);
	unsigned int edx = REG32_INDX(REG_EDX);

	Taint::iterator tb = thread_info[tid].reg_taint[reg].begin();
	Taint::iterator te = thread_info[tid].reg_taint[reg].end();

	for(int i = 0; i < 4; ++i) {
		thread_info[tid].reg_taint[eax + i].insert(tb ,te);
		thread_info[tid].reg_taint[edx + i].insert(tb ,te);
	}
}

void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opw(unsigned int reg, THREADID tid)// affect ax and dx
{
	unsigned int ax = REG16_INDX(REG_AX);
	unsigned int dx = REG16_INDX(REG_DX);

	Taint::iterator tb = thread_info[tid].reg_taint[reg].begin();
	Taint::iterator te = thread_info[tid].reg_taint[reg].end();

	thread_info[tid].reg_taint[ax].insert(tb, te);
	thread_info[tid].reg_taint[ax + 1].insert(tb, te);

	thread_info[tid].reg_taint[dx].insert(tb, te);
	thread_info[tid].reg_taint[dx + 1].insert(tb, te);
}

void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb(unsigned int reg, THREADID tid)// affect ax
{
	unsigned int ax = REG32_INDX(REG_AX);

	Taint::iterator tb = thread_info[tid].reg_taint[reg].begin();
	Taint::iterator te = thread_info[tid].reg_taint[reg].end();

	thread_info[tid].reg_taint[ax].insert(tb, te);
	thread_info[tid].reg_taint[ax + 1].insert(tb, te);
}

// cmpxchg, reg
ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_fast(unsigned int dst_val, unsigned int src, unsigned int src_val, THREADID tid)
{
	unsigned int eax = REG32_INDX(REG_EAX);
	for(int i = 0; i < 4; ++i) {
		// backup eax
		thread_info[tid].reg_taint[GPR_MEMS + i] = thread_info[tid].reg_taint[eax + i];
		// eax = src
		thread_info[tid].reg_taint[eax + i] = thread_info[tid].reg_taint[src + i];
	}
	return (dst_val == src_val);
}

void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_slow(unsigned int dst, unsigned int src, THREADID tid)
{
	unsigned int eax = REG32_INDX(REG_EAX);
	for(int i = 0; i < 4; ++i) {
		// restore eax
		thread_info[tid].reg_taint[eax + i] = thread_info[tid].reg_taint[GPR_MEMS + i];
		// dst <-- src
		thread_info[tid].reg_taint[dst + i] = thread_info[tid].reg_taint[src + i];
	}
}

ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_fast(unsigned int dst_val, unsigned int src, unsigned int src_val, THREADID tid)
{
	unsigned int ax = REG16_INDX(REG_EAX);
	for(int i = 0; i < 2; ++i) {
		// backup eax
		thread_info[tid].reg_taint[GPR_MEMS + i] = thread_info[tid].reg_taint[ax + i];
		// eax = src
		thread_info[tid].reg_taint[ax + i] = thread_info[tid].reg_taint[src + i];
	}
	return (dst_val == src_val);
}

void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_slow(unsigned int dst, unsigned int src, THREADID tid)
{
	unsigned int ax = REG32_INDX(REG_EAX);
	for(int i = 0; i < 2; ++i) {
		// restore eax
		thread_info[tid].reg_taint[ax + i] = thread_info[tid].reg_taint[GPR_MEMS + i];
		// dst <-- src
		thread_info[tid].reg_taint[dst + i] = thread_info[tid].reg_taint[src + i];
	}
}

// cmpxchg, mem
ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opl_fast(unsigned int dst_val, ADDRINT src, THREADID tid)
{
	unsigned int eax = REG32_INDX(REG_EAX);
	TaintMap::iterator it;
	for(int i = 0; i < 4; ++i) {
		// backup eax
		thread_info[tid].reg_taint[GPR_MEMS + i] = thread_info[tid].reg_taint[eax + i];
		// eax = src
		it = taintMap.find(src + i);
		if(it != taintMap.end()) {
			thread_info[tid].reg_taint[eax + i] = it->second;
		} else {
			thread_info[tid].reg_taint[eax + i].clear();
		}
	}
	return (dst_val == *(unsigned int *)src);
}
void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opl_slow(ADDRINT dst, unsigned int src, THREADID tid)
{
	unsigned int eax = REG32_INDX(REG_EAX);
	for(int i = 0; i < 4; ++i) {
		// restore eax
		thread_info[tid].reg_taint[eax + i] = thread_info[tid].reg_taint[GPR_MEMS + i];
		// dst <-- src
		Taint &t = thread_info[tid].reg_taint[src + i];
		if(t.size() != 0) {
			taintMap[dst + i] = t;
		} else {
			if(taintMap.find(dst + i) != taintMap.end())
				taintMap.erase(dst + i);
		}
	}
}

ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opw_fast(unsigned short dst_val, ADDRINT src, THREADID tid)
{
	unsigned int ax = REG32_INDX(REG_AX);
	TaintMap::iterator it;
	for(int i = 0; i < 2; ++i) {
		// backup eax
		thread_info[tid].reg_taint[GPR_MEMS + i] = thread_info[tid].reg_taint[ax + i];
		// eax = src
		it = taintMap.find(src + i);
		if(it != taintMap.end()) {
			thread_info[tid].reg_taint[ax + i] = it->second;
		} else {
			thread_info[tid].reg_taint[ax + i].clear();
		}
	}
	return (dst_val == *(unsigned short *)src);
}

void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opw_slow(ADDRINT dst, unsigned int src, THREADID tid)
{
	unsigned int ax = REG32_INDX(REG_AX);
	for(int i = 0; i < 2; ++i) {
		// restore eax
		thread_info[tid].reg_taint[ax + i] = thread_info[tid].reg_taint[GPR_MEMS + i];
		// dst <-- src
		Taint &t = thread_info[tid].reg_taint[src + i];
		if(t.size() != 0) {
			taintMap[dst + i] = t;
		} else {
			if(taintMap.find(dst + i) != taintMap.end())
				taintMap.erase(dst + i);
		}
	}
}

// xchg, reg <--> reg
void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opw(unsigned int dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 2; ++i) {
		_xchg_r2r_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb(unsigned int dst, unsigned int src, THREADID tid)
{
	Taint t = thread_info[tid].reg_taint[dst];

	thread_info[tid].reg_taint[dst] = thread_info[tid].reg_taint[src];
	thread_info[tid].reg_taint[src] = t;
}

// xchg, reg <--> mem
void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opl(unsigned int dst, ADDRINT src, THREADID tid)
{
	for(int i = 0; i < 4; ++i) {
		_xchg_m2r_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opw(unsigned int dst, ADDRINT src, THREADID tid)
{
	for(int i = 0; i < 2; ++i) {
		_xchg_m2r_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb(unsigned int dst, ADDRINT src, THREADID tid)
{
	Taint t = thread_info[tid].reg_taint[dst];// can't use reference here!!!

	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[dst] = it->second;
	} else {
		thread_info[tid].reg_taint[dst].clear();
	}

	if(t.size() != 0) {
		taintMap[src] = t;
	} else {
		if(it != taintMap.end())
			taintMap.erase(src);
	}
}

// xadd, reg reg
void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opl(unsigned int dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 4; ++i) {
		_xadd_r2r_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opw(unsigned int dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 2; ++i) {
		_xadd_r2r_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb(unsigned int dst, unsigned int src, THREADID tid)
{
	Taint t = thread_info[tid].reg_taint[dst];
	r2r_binary_opb(dst, src, tid);

	thread_info[tid].reg_taint[src] = t;
}

// xadd, mem reg
void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opl(ADDRINT dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 4; ++i) {
		_xadd_r2m_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opw(ADDRINT dst, unsigned int src, THREADID tid)
{
	for(int i = 0; i < 2; ++i) {
		_xadd_r2m_opb(dst + i, src + i, tid);
	}
}

void PIN_FAST_ANALYSIS_CALL
_xadd_r2m_opb(ADDRINT dst, unsigned int src, THREADID tid)
{
	TaintMap::iterator it = taintMap.find(dst);
	Taint t;
	if(it != taintMap.end()) {
		t = it->second;
	}

	r2m_binary_opb(dst, src, tid);

	if(it != taintMap.end()) {
		thread_info[tid].reg_taint[src] = t;
	} else {
		thread_info[tid].reg_taint[src].clear();
	}
}

// rep store or load
ADDRINT PIN_FAST_ANALYSIS_CALL
rep_predicate(BOOL first_iteration)
{
	return first_iteration;
}

void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opbn(ADDRINT dst, ADDRINT count, ADDRINT eflags, THREADID tid)// 1997
{
	Taint *t = &thread_info[tid].reg_taint[REG8_INDX(REG_AL)];

	if(EFLAGS_DF(eflags) == 0) {
		if(t->size() != 0) {
			tagmap_setn(dst, count, t);
		} else {
			tagmap_clrn(dst, count);
		}
	} else {
		if(t->size() != 0) {
			tagmap_setn(dst - count + 1, count, t);
		} else {
			tagmap_clrn(dst - count + 1, count);
		}
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opwn(ADDRINT dst, ADDRINT count, ADDRINT eflags, THREADID tid)
{
	Taint *t = &thread_info[tid].reg_taint[REG16_INDX(REG_AX)];
	if(EFLAGS_DF(eflags) == 0) {
		if(t->size() != 0) {
			tagmap_setn(dst, (count << 1), t, 2);
		} else {
			tagmap_clrn(dst, (count << 1));
		}
	} else {
		if(t->size() != 0) {
			tagmap_setn(dst - count + 1, (count << 1), t, 2);
		} else {
			tagmap_clrn(dst - count + 1, (count << 1));
		}
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opln(ADDRINT dst, ADDRINT count, ADDRINT eflags, THREADID tid)
{
	Taint *t = &thread_info[tid].reg_taint[REG32_INDX(REG_EAX)];

	if(EFLAGS_DF(eflags) == 0) {
		if(t->size() != 0) {
			tagmap_setn(dst, (count << 2), t, 4);
		} else {
			tagmap_clrn(dst, (count << 2));
		}
	} else {
		if(t->size() != 0) {
			tagmap_setn(dst - count + 1, (count << 2), t, 4);
		} else {
			tagmap_clrn(dst - count + 1, (count << 2));
		}
	}
}

//
void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opl(ADDRINT dst, ADDRINT src)
{
	for(int i = 0; i < 4; ++i) {
		m2m_xfer_opb(dst + i, src + i);
	}
}

void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opw(ADDRINT dst, ADDRINT src)
{
	for(int i = 0; i < 2; ++i) {
		m2m_xfer_opb(dst + i, src + i);
	}
}

void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opb(ADDRINT dst, ADDRINT src)
{
	TaintMap::iterator it = taintMap.find(src);
	if(it != taintMap.end()) {
		taintMap[dst] = it->second;
	} else {
		taintMap.erase(dst);
	}
}

// popa
void PIN_FAST_ANALYSIS_CALL
m2r_restore_opw(ADDRINT src, THREADID tid)
{
	for(size_t i = 0; i < GPR_MEMS; i += 4) {
		if(i == REG16_INDX(REG_SP)) continue;

		for(size_t j = 0; j < 2; ++j) {
			TaintMap::iterator it = taintMap.find(src++);
			if(it != taintMap.end()) {
				thread_info[tid].reg_taint[i + j] = it->second;
			} else {
				thread_info[tid].reg_taint[i + j].clear();
			}
		}
	}
}

void PIN_FAST_ANALYSIS_CALL
m2r_restore_opl(ADDRINT src, THREADID tid)
{
	for(size_t i = 0; i < GPR_MEMS; i += 4) {
		if(i == REG32_INDX(REG_ESP)) continue;

		for(size_t j = 0; j < 4; ++j) {
			TaintMap::iterator it = taintMap.find(src++);
			if(it != taintMap.end()) {
				thread_info[tid].reg_taint[i + j] = it->second;
			} else {
				thread_info[tid].reg_taint[i + j].clear();
			}
		}
	}
}

// pusha
void PIN_FAST_ANALYSIS_CALL
r2m_save_opw(ADDRINT dst, THREADID tid)
{
	for(size_t i = 0; i < GPR_MEMS; i += 4) {
		for(size_t j = 0; j < 2; ++j) {
			Taint &t = thread_info[tid].reg_taint[i + j];
			if(t.size() != 0) {
				taintMap[dst] = t;
			} else {
				if(taintMap.find(dst) != taintMap.end())
					taintMap.erase(dst);
			}
			dst++;
		}
	}
}

void PIN_FAST_ANALYSIS_CALL
r2m_save_opl(ADDRINT dst, THREADID tid)
{
	for(size_t i = 0; i < GPR_MEMS; i += 4) {
		for(size_t j = 0; j < 4; ++j) {
			Taint &t = thread_info[tid].reg_taint[i + j];
			if(t.size() != 0) {
				taintMap[dst] = t;
			} else {
				if(taintMap.find(dst) != taintMap.end())
					taintMap.erase(dst);
			}
			dst++;
		}
	}
}

/*
 *
 * here, we ignore base+index relationship, just for simplicity
 * [base + index]
 * MSB in fact is influenced by LSB or the ISB(intermediate)
 *
 */
// lea
void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opl(unsigned int dst, unsigned int base, unsigned int index, THREADID tid)
{
	for(size_t i = 0; i < 4; ++i) {
		Taint &t_dst = thread_info[tid].reg_taint[dst + i];
		t_dst = thread_info[tid].reg_taint[base + i];// use base to update
		
		Taint &t_indx = thread_info[tid].reg_taint[index + i];
		t_dst.insert(t_indx.begin(), t_indx.end());// use indx to add
	}
}

void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opw(unsigned int dst, unsigned int base, unsigned int index, THREADID tid)
{
	for(size_t i = 0; i < 2; ++i) {
		Taint &t_dst = thread_info[tid].reg_taint[dst + i];
		t_dst = thread_info[tid].reg_taint[base + i];// use base to update
		
		Taint &t_indx = thread_info[tid].reg_taint[index + i];
		t_dst.insert(t_indx.begin(), t_indx.end());// use indx to add
	}
}










