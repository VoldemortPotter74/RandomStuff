#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <stddef.h>

// CmdManager_ReadOutput return codes
#define CMDM_STATUS_SUCCESS 0
#define CMDM_STATUS_ERROR   1
#define CMDM_STATUS_NO_DATA 2

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
__declspec(dllexport) DWORD WINAPI CmdManager_ExecuteCmd(const char* cmd, DWORD cmdLength);

// Caller owns *o_ppbOutput and must free() it.
__declspec(dllexport) DWORD WINAPI CmdManager_ReadOutput(PBYTE* o_ppbOutput, DWORD* o_pdwOutputLen);

__declspec(dllexport) VOID WINAPI CmdManager_FreeOutput(PBYTE pbBuffer);
