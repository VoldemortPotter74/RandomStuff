#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <stddef.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#define AES_KEY_SIZE (32)
#define KEY_TEXT ("If you see this, get a life!!!")

typedef struct _COMMUNICATION_MANAGER{
    SOCKET m_socket;
    BYTE m_abAesKey[AES_KEY_SIZE];
    WSAEVENT m_hSocketRecvEvent;
    WSAEVENT m_hSocketSendEvent;
    HANDLE m_hTerminateEvent;
} COMMUNICATION_MANAGER, *PCOMMUNICATION_MANAGER;

typedef struct _COMMAND{
    DWORD m_dwCommandId;
    DWORD m_dwDataLength;
    BYTE* m_pbData;
} COMMAND, * PCOMMAND;

typedef enum _COMM_MANAGER_RETURN_VALUES
{
    COMM_MANAGER_SUCCESS = 0,
    COMM_MANAGER_INVALID_PARAMETERS,
    COMM_MANAGER_ERROR,
    COMM_MANAGER_TERMINATE,
} COMM_MANAGER_RETURN_VALUES;

COMM_MANAGER_RETURN_VALUES CommunicationManager_ConnectToServer(const LPCWSTR i_wszHost, const LPCWSTR i_wszPort, PCOMMUNICATION_MANAGER o_pCommunicationManager);
COMM_MANAGER_RETURN_VALUES CommunicationManager_ReceiveCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, PCOMMAND o_pCommand);
COMM_MANAGER_RETURN_VALUES CommunicationManager_SendCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, DWORD i_dwCommandId, const BYTE* i_pbData, DWORD i_dwDataLength);
VOID CommunicationManager_Disconnect(PCOMMUNICATION_MANAGER io_pCommunicationManager);