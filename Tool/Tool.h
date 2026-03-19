#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <NTSecAPI.h>
#include <ntsecpkg.h>

#define CONFIGURATION ("default")
#define DEFAULT_SLEEP_TIME (10)
#define TOOL_ID (0x6767)

typedef enum {
    KEEP_ALIVE_COMMAND_ID = 0,
    GET_CONFIGURATION_COMMAND_ID = 1,
    SET_TOOL_ID_COMMAND_ID = 2,
} SENT_COMMAND_ID;

typedef enum {
    TERMINATE_COMMAND_ID = 0,
    LOAD_COMMAND_ID = 3,
    UNLOAD_COMMAND_ID = 4,
    EXECUTE_CMD_COMMAND_ID = 5,
} RECEIVED_COMMAND_ID;

__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
