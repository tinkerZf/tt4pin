#pragma once

#include <list>
#include <set>
#include <map>
#include <iostream>
#include <fstream>
using namespace std;

#include "pin.H"
#include "TaintFile.h"
#include "TaintTracer.h"
#include "dft_core.h"

#ifdef _WIN32

namespace WINDOWS {
#include "Winsock2.h"
#include "Windows.h"
}


typedef WINDOWS::HANDLE HANDLE;
typedef int DWORD;
typedef WINDOWS::LPCTSTR LPCTSTR;
typedef const VOID *LPCVOID;

#endif

