#include "CmdManager.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    PROCESS_INFORMATION processInfo;
    HANDLE hStdin;
    HANDLE hStdout;
} CmdProcessInfo;

static CmdProcessInfo g_cmdProcessInfo = { 0 };

static BOOL startCmdProcess(VOID);
static VOID cleanupCmdProcess(VOID);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        startCmdProcess();
        break;

    case DLL_PROCESS_DETACH:
        cleanupCmdProcess();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

static BOOL startCmdProcess(VOID) {
    // In case startCmdProcess is called more than once, ensure we
    // release any previous handles before overwriting globals.
    cleanupCmdProcess();

    SECURITY_ATTRIBUTES sa = { 0 };
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE stdinPipe[2] = { 0 };
    HANDLE stdoutPipe[2] = { 0 };

    if (!CreatePipe(&stdinPipe[0], &stdinPipe[1], &sa, 0)) {
        return FALSE;
    }

    if (!CreatePipe(&stdoutPipe[0], &stdoutPipe[1], &sa, 0)) {
        CloseHandle(stdinPipe[0]);
        CloseHandle(stdinPipe[1]);
        return FALSE;
    }

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = stdinPipe[0];
    si.hStdOutput = stdoutPipe[1];
    si.hStdError = stdoutPipe[1];

    PROCESS_INFORMATION pi = { 0 };
    char* cmdLine = "cmd.exe /Q /D /K";
    BOOL success = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    CloseHandle(stdinPipe[0]);
    CloseHandle(stdoutPipe[1]);

    if (!success) {
        CloseHandle(stdinPipe[1]);
        CloseHandle(stdoutPipe[0]);
        return FALSE;
    }

    g_cmdProcessInfo.processInfo = pi;
    g_cmdProcessInfo.hStdin = stdinPipe[1];
    g_cmdProcessInfo.hStdout = stdoutPipe[0];

    // Ownership of the process/thread handles is now in g_cmdProcessInfo.
    // Clearing locals helps static analysis understand they are not leaked.
    pi.hProcess = NULL;
    pi.hThread = NULL;

    return TRUE;
}

static VOID cleanupCmdProcess(VOID) {
    if (g_cmdProcessInfo.hStdin != NULL && g_cmdProcessInfo.hStdin != INVALID_HANDLE_VALUE) {
        CloseHandle(g_cmdProcessInfo.hStdin);
        g_cmdProcessInfo.hStdin = NULL;
    }

    if (g_cmdProcessInfo.hStdout != NULL && g_cmdProcessInfo.hStdout != INVALID_HANDLE_VALUE) {
        CloseHandle(g_cmdProcessInfo.hStdout);
        g_cmdProcessInfo.hStdout = NULL;
    }

    if (g_cmdProcessInfo.processInfo.hProcess != NULL && g_cmdProcessInfo.processInfo.hProcess != INVALID_HANDLE_VALUE) {
        TerminateProcess(g_cmdProcessInfo.processInfo.hProcess, 0);
        CloseHandle(g_cmdProcessInfo.processInfo.hProcess);
        g_cmdProcessInfo.processInfo.hProcess = NULL;
    }

    if (g_cmdProcessInfo.processInfo.hThread != NULL && g_cmdProcessInfo.processInfo.hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(g_cmdProcessInfo.processInfo.hThread);
        g_cmdProcessInfo.processInfo.hThread = NULL;
    }
}

DWORD WINAPI CmdManager_ExecuteCmd(const char* cmd, DWORD cmdLength) {
    if (!cmd || cmdLength == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    if (cmdLength > MAXDWORD - 2) {
        return ERROR_INVALID_PARAMETER;
    }

    if (g_cmdProcessInfo.hStdin == NULL || g_cmdProcessInfo.hStdout == NULL) {
        return ERROR_NOT_READY;
    }

    char* cmdString = (char*)malloc(cmdLength + 3);
    if (!cmdString) {
        return ERROR_OUTOFMEMORY;
    }

    memcpy(cmdString, cmd, cmdLength);
    cmdString[cmdLength] = '\r';
    cmdString[cmdLength + 1] = '\n';
    cmdString[cmdLength + 2] = '\0';

    DWORD written = 0;
    if (!WriteFile(g_cmdProcessInfo.hStdin, cmdString, (DWORD)(cmdLength + 2), &written, NULL)) {
        free(cmdString);
        return GetLastError();
    }

    free(cmdString);
    return 0;
}

DWORD WINAPI CmdManager_ReadOutput(PBYTE* o_ppbOutput, DWORD* o_pdwOutputLen) {
    if (!o_ppbOutput || !o_pdwOutputLen) {
        return CMDM_STATUS_ERROR;
    }

    *o_ppbOutput = NULL;
    *o_pdwOutputLen = 0;

    if (g_cmdProcessInfo.hStdout == NULL || g_cmdProcessInfo.hStdout == INVALID_HANDLE_VALUE) {
        return CMDM_STATUS_ERROR;
    }

    DWORD bytesAvailable = 0;
    if (!PeekNamedPipe(g_cmdProcessInfo.hStdout, NULL, 0, NULL, &bytesAvailable, NULL)) {
        return CMDM_STATUS_ERROR;
    }

    if (bytesAvailable == 0) {
        return CMDM_STATUS_NO_DATA;
    }

    const DWORD chunkSize = 4096;
    DWORD total = 0;
    PBYTE out = NULL;

    while (TRUE) {
        DWORD availNow = 0;
        if (!PeekNamedPipe(g_cmdProcessInfo.hStdout, NULL, 0, NULL, &availNow, NULL)) {
            free(out);
            return CMDM_STATUS_ERROR;
        }

        if (availNow == 0) {
            break;
        }

        DWORD toRead = (availNow > chunkSize) ? chunkSize : availNow;
        PBYTE newOut = (PBYTE)realloc(out, (size_t)total + (size_t)toRead);
        if (!newOut) {
            free(out);
            return CMDM_STATUS_ERROR;
        }
        out = newOut;

        DWORD bytesRead = 0;
        if (!ReadFile(g_cmdProcessInfo.hStdout, out + total, toRead, &bytesRead, NULL)) {
            free(out);
            return CMDM_STATUS_ERROR;
        }

        if (bytesRead == 0) {
            break;
        }

        total += bytesRead;
    }

    if (total == 0) {
        free(out);
        return CMDM_STATUS_NO_DATA;
    }

    *o_ppbOutput = out;
    *o_pdwOutputLen = total;
    return CMDM_STATUS_SUCCESS;
}

VOID WINAPI CmdManager_FreeOutput(PBYTE pbBuffer)
{
    free(pbBuffer);
}
