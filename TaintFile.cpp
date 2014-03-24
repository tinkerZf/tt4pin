#pragma once

#include "TaintFile.h"
#include "dft_core.h"

std::set<WINDOWS::HANDLE>  g_hTaintFile;

std::string& to_string(std::string& dest, std::wstring const & src)
{
	setlocale(LC_CTYPE, "");
	//get src's size
	size_t const mbs_len = wcstombs(NULL, src.c_str(), 0);
	std::vector<char> tmp(mbs_len + 1);
	wcstombs(&tmp[0], src.c_str(), tmp.size());

	dest.assign(tmp.begin(), tmp.end() - 1);

	return dest;
}

WINDOWS::HANDLE CreateFileWWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid,
	wchar_t* lpFileName,
	DWORD dwDesiredAccess, 
	DWORD dwShareMode,
	WINDOWS::LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	HANDLE ret;

	PIN_CallApplicationFunction(ctx, tid, CALLINGSTD_STDCALL, fp,
		PIN_PARG(HANDLE), &ret,
		PIN_PARG(wchar_t*), lpFileName,
		PIN_PARG(DWORD), dwDesiredAccess,
		PIN_PARG(DWORD), dwShareMode,
		PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES), lpSecurityAttributes,
		PIN_PARG(DWORD), dwCreationDisposition,
		PIN_PARG(DWORD), dwFlagsAndAttributes,
		PIN_PARG(HANDLE), hTemplateFile,
		PIN_PARG_END());

	{
		std::wstring filename = lpFileName;
		std::string filenameA;
		filenameA = to_string(filenameA, filename);

		//FIXME: XXX
		if (strstr(filenameA.c_str(),".txt") != NULL)
		{
			if (ret != (WINDOWS::HANDLE)-1)
			{
				g_hTaintFile.insert(ret);
				OutFile << "TaintFile: " << filenameA << 
					" , Handle: 0x"<< ret <<endl;
			}
			else
			{
				OutFile << "CreateFileW TaintFile Error..." << endl;
			}
		}
	}

	return ret;
}

/* ReadFile Protocol
BOOL ReadFile(
HANDLE hFile,                // handle of file to read
LPVOID lpBuffer,             // pointer to buffer that receives data
DWORD nNumberOfBytesToRead,  // number of bytes to read
LPDWORD lpNumberOfBytesRead, // pointer to number of bytes read
LPOVERLAPPED lpOverlapped    // pointer to structure for data
);

*/
BOOL ReadFileWrapper(CONTEXT *ctx, AFUNPTR fp, THREADID tid, WINDOWS::HANDLE hFile, void* lpBuffer, int nNumberOfBytesToRead,int* lpNumberOfBytesRead, WINDOWS::LPOVERLAPPED lpOverlapped)
{
	DWORD pos = 0;
	if (g_hTaintFile.find(hFile) != g_hTaintFile.end())
	{
		pos = WINDOWS::SetFilePointer(hFile,0,NULL,FILE_CURRENT);
	}

	BOOL ret;
	PIN_CallApplicationFunction(ctx, tid,
		CALLINGSTD_STDCALL, fp,
		PIN_PARG(BOOL), &ret,
		PIN_PARG(HANDLE), hFile,
		PIN_PARG(void*), lpBuffer,
		PIN_PARG(int), nNumberOfBytesToRead,
		PIN_PARG(int*), lpNumberOfBytesRead,
		PIN_PARG(WINDOWS::LPOVERLAPPED), lpOverlapped,
		PIN_PARG_END());

	{
		if (g_hTaintFile.find(hFile) != g_hTaintFile.end())
		{
			//在此处加入污点源标记
			for (int i=0; i < *lpNumberOfBytesRead; i++)
			{
				Taint t; t.insert((ADDRINT)lpBuffer);
				taintMap.insert(make_pair((ADDRINT)lpBuffer, t));
				//addressTainted.push_back((DWORD)lpBuffer + i);
			}

			char temp[1024] = {0};
			sprintf(temp,"(0x%08x,0x%08x) -> 0x%08x\n",pos,*lpNumberOfBytesRead,lpBuffer);
			OutFile << temp;
		}
	}

	return ret;
}


VOID TaintFile(IMG img, VOID *v)
{
	ADDRINT low_addr = IMG_LowAddress(img);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
	ADDRINT high_addr = IMG_HighAddress(img);
	ADDRINT start_addr = IMG_StartAddress(img);
	ADDRINT load_offset = IMG_LoadOffset(img);

	const string &name = IMG_Name(img);

	char tempbuf[MAX_PATH];
	char *tok = NULL;
	char *lasttok = NULL;

	// Fill up the temporary buffer
	strncpy(tempbuf, name.c_str(), MAX_PATH);

	// We don't need a lock, since this is an instrumentation function (strtok is not re-entrant)
	strtok(tempbuf, "\\");

	while ((tok = strtok(NULL, "\\")) != NULL) 
	{
		// Just keep parsing...
		lasttok = tok;
	}

	if (lasttok == NULL) return; 

	if (strncmp("kernel32.dll", lasttok, MAX_PATH) == 0)
	{
		RTN r;
		r = RTN_FindByName(img, "CreateFileW");
		if (r != RTN_Invalid()) 
		{
			PROTO proto = PROTO_Allocate(PIN_PARG(HANDLE), CALLINGSTD_STDCALL,
				"CreateFileW",
				PIN_PARG(LPCTSTR ),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(WINDOWS::LPSECURITY_ATTRIBUTES),
				PIN_PARG(DWORD),
				PIN_PARG(DWORD),
				PIN_PARG(HANDLE),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(CreateFileWWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
				IARG_END);


			PROTO_Free(proto);

		}
		else 
		{
			OutFile << "Couldn't find CreateFileW" << endl;
		}

		r = RTN_FindByName(img, "ReadFile");
		if (r != RTN_Invalid()) 
		{


			PROTO proto = PROTO_Allocate(PIN_PARG(BOOL), CALLINGSTD_STDCALL,
				"ReadFile",
				PIN_PARG(WINDOWS::HANDLE),
				PIN_PARG(void*),
				PIN_PARG(int),
				PIN_PARG(int*),
				PIN_PARG(WINDOWS::LPOVERLAPPED ),
				PIN_PARG_END());

			RTN_ReplaceSignature(r, AFUNPTR(ReadFileWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
				IARG_END);


			PROTO_Free(proto);

		}
		else 
		{
			OutFile << "Couldn't find ReadFile" << endl;
		}

	}
}