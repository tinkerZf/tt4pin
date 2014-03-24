/*
	Taint Tracer Pintool
	nforest @ k33nteam
*/

#pragma once
#include "ttracer.h"

ofstream OutFile;
PIN_LOCK lock;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "ttracer.log", "specify output file name");

// globle variables
TaintMap taintMap;
per_thread thread_info[MAX_NUM_CPUS];

bool setb = false;


VOID ImageLoad(IMG img, VOID *v)
{
	//CreateFileW() ReadFile()
	//FIXME: CloseHandle CreateFileMappingW MapViewOfFile
	TaintFile(img,v);
}


VOID TaintTrace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) 
	{
		OutFile << "====================New Block Here====================" << endl;
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			TaintTracer(ins);
		}
	}
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
	TaintTracer(ins);
}

VOID ThreadStart(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	//
	PIN_GetLock(&lock, tid+1);
	thread_info[tid].taint_prop = true;
	OutFile << "Thread " << tid << " begin" << endl << flush;
	PIN_ReleaseLock(&lock);
}
VOID ThreadFini(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *v)
{
	PIN_GetLock(&lock, tid+1);
	thread_info[tid].taint_prop = false;
	OutFile << "Thread " << tid << " end code " << code << endl << flush;
	PIN_ReleaseLock(&lock);
}


// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	OutFile.close();
}

INT32 Usage()
{
	cerr << "pin.exe -t ttracer.dll -x taint.txt -o output.txt -- target.exe [args]" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

int main(int argc, char * argv[])
{
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	OutFile.open(KnobOutputFile.Value().c_str());
	OutFile << "Start..." << endl;


	PIN_InitSymbols();
	
	IMG_AddInstrumentFunction(ImageLoad, 0); 

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Register Instruction to be called to instrument instructions
	TRACE_AddInstrumentFunction(TaintTrace, 0);

	//INS_AddInstrumentFunction(Instruction,0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
