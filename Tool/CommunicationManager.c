#include "CommunicationManager.h"
#include <stdlib.h>
#include <string.h>

#define MAX_CHUNK_SIZE (0x1000)

typedef enum _COMM_MANAGER_INNER_RETURN_VALUES
{
    COMM_MANAGER_INNER_SUCCESS = 0,
    COMM_MANAGER_INNER_INVALID_PARAMETERS,
    COMM_MANAGER_INNER_OUT_OF_MEMORY,
    COMM_MANAGER_INNER_PROTOCOL_ERROR,
    COMM_MANAGER_INNER_GENERAL_ERROR,
    COMM_MANAGER_INNER_TERMINATE,
} COMM_MANAGER_INNER_RETURN_VALUES;

static BOOLEAN g_bIsWSASetUp = FALSE;

static COMM_MANAGER_INNER_RETURN_VALUES initializeWinsock(VOID);
static COMM_MANAGER_INNER_RETURN_VALUES waitAndRecv(PCOMMUNICATION_MANAGER i_pCommunicationManager, PVOID o_pBuffer, int i_iBufferLength, int i_iFlags, int* o_pNumberOfBytesReceived);
static COMM_MANAGER_INNER_RETURN_VALUES waitAndSend(PCOMMUNICATION_MANAGER i_pCommunicationManager, PVOID o_pBuffer, int i_iBufferLength, int i_iFlags, int* o_pNumberOfBytesReceived);
static COMM_MANAGER_INNER_RETURN_VALUES recvExact(PCOMMUNICATION_MANAGER i_pCommunicationManager, const PVOID o_pBuffer, const SIZE_T i_nBufferSize, const int i_iFlags);
static COMM_MANAGER_INNER_RETURN_VALUES sendExact(PCOMMUNICATION_MANAGER i_pCommunicationManager, const PVOID o_pBuffer, const SIZE_T i_nBufferSize, const int i_iFlags);
static COMM_MANAGER_INNER_RETURN_VALUES encryptData(
    const BYTE* i_pbKey,
    const BYTE* i_pbPlainText,
    DWORD i_dwPlainTextLen,
    PBYTE* o_ppbCipherText,
    DWORD* o_pdwCipherTextLen);
static COMM_MANAGER_INNER_RETURN_VALUES decryptData(
    const BYTE* i_pbKey,
    const BYTE* i_pbCipherText,
    DWORD i_dwCipherTextLen,
    PBYTE* o_ppbPlainText,
    DWORD* o_pdwPlainTextLen);
static COMM_MANAGER_INNER_RETURN_VALUES sendEncryptedPacket(PCOMMUNICATION_MANAGER i_pCommunicationManager, const BYTE* i_pbData, DWORD i_dwDataLen);
static COMM_MANAGER_INNER_RETURN_VALUES receiveEncryptedPacket(PCOMMUNICATION_MANAGER i_pCommunicationManager, PBYTE* o_ppbBuffer, DWORD* o_pdwBufferLen);
static BOOLEAN communicationManagerSanityCheck(PCOMMUNICATION_MANAGER i_pCommunicationManager);

static COMM_MANAGER_INNER_RETURN_VALUES initializeWinsock(VOID)
{
    WSADATA wsaData;

    if (g_bIsWSASetUp)
    {
        return COMM_MANAGER_INNER_SUCCESS;
    }

    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) 
    {
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) 
    {
        WSACleanup();
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    g_bIsWSASetUp = TRUE;

    return COMM_MANAGER_INNER_SUCCESS;
}

static COMM_MANAGER_INNER_RETURN_VALUES waitAndRecv(PCOMMUNICATION_MANAGER i_pCommunicationManager, PVOID o_pBuffer, int i_iBufferLength, int i_iFlags, int* o_piNumberOfBytesReceived)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        (NULL == o_pBuffer) ||
        (0 == i_iBufferLength) ||
        (NULL == o_piNumberOfBytesReceived)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    *o_piNumberOfBytesReceived = 0;

    HANDLE ahEvents[2] = { 0 };
    ahEvents[0] = i_pCommunicationManager->m_hTerminateEvent;
    ahEvents[1] = i_pCommunicationManager->m_hSocketRecvEvent;

    DWORD dwWaitStatus = WaitForMultipleObjects(2, ahEvents, FALSE, INFINITE);
    if (0 == dwWaitStatus - WAIT_OBJECT_0)
    {
        return COMM_MANAGER_INNER_TERMINATE;
    }
    else if (1 != dwWaitStatus - WAIT_OBJECT_0)
    {
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    int iNumberOfBytesReceived = recv(i_pCommunicationManager->m_socket, o_pBuffer, i_iBufferLength, i_iFlags);
    if ((0 == iNumberOfBytesReceived) || (SOCKET_ERROR == iNumberOfBytesReceived))
    {
        return COMM_MANAGER_INNER_PROTOCOL_ERROR;
    }

    *o_piNumberOfBytesReceived = iNumberOfBytesReceived;

    return COMM_MANAGER_INNER_SUCCESS;
}

static COMM_MANAGER_INNER_RETURN_VALUES waitAndSend(PCOMMUNICATION_MANAGER i_pCommunicationManager, PVOID o_pBuffer, int i_iBufferLength, int i_iFlags, int* o_piNumberOfBytesSent)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        (NULL == o_pBuffer) ||
        (0 == i_iBufferLength) ||
        (NULL == o_piNumberOfBytesSent)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    HANDLE ahEvents[2] = { 0 };
    ahEvents[0] = i_pCommunicationManager->m_hTerminateEvent;
    ahEvents[1] = i_pCommunicationManager->m_hSocketSendEvent;

    DWORD dwWaitStatus = WaitForMultipleObjects(2, ahEvents, FALSE, INFINITE);
    if (0 == dwWaitStatus - WAIT_OBJECT_0)
    {
        return COMM_MANAGER_INNER_TERMINATE;
    }
    else if (1 != dwWaitStatus - WAIT_OBJECT_0)
    {
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    int iNumberOfBytesSent = send(i_pCommunicationManager->m_socket, o_pBuffer, i_iBufferLength, i_iFlags);
    if (SOCKET_ERROR == iNumberOfBytesSent)
    {
        return COMM_MANAGER_INNER_PROTOCOL_ERROR;
    }

    *o_piNumberOfBytesSent = iNumberOfBytesSent;

    return COMM_MANAGER_INNER_SUCCESS;
}

static COMM_MANAGER_INNER_RETURN_VALUES recvExact(PCOMMUNICATION_MANAGER i_pCommunicationManager, const PVOID o_pBuffer, const SIZE_T i_nBufferSize, const int i_iFlags)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        (NULL == o_pBuffer) ||
        (0 == i_nBufferSize)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    PBYTE pbBuffer = o_pBuffer;

    SIZE_T nTotalNumOfBytesReceived = 0;

    while (i_nBufferSize > nTotalNumOfBytesReceived)
    {
        DWORD dwNumOfBytesToReceive = (DWORD)min((i_nBufferSize - nTotalNumOfBytesReceived), MAX_CHUNK_SIZE);

        DWORD dwNumOfBytesReceived = 0;

        COMM_MANAGER_INNER_RETURN_VALUES nReturnValue = COMM_MANAGER_INNER_SUCCESS;

        nReturnValue = waitAndRecv(i_pCommunicationManager, pbBuffer + nTotalNumOfBytesReceived, dwNumOfBytesToReceive, i_iFlags, &dwNumOfBytesReceived);
        if (COMM_MANAGER_INNER_SUCCESS != nReturnValue)
        {
            return nReturnValue;
        }

        nTotalNumOfBytesReceived += dwNumOfBytesReceived;
    }

    return COMM_MANAGER_INNER_SUCCESS;
}

static COMM_MANAGER_INNER_RETURN_VALUES sendExact(PCOMMUNICATION_MANAGER i_pCommunicationManager, const PVOID o_pBuffer, const SIZE_T i_nBufferSize, const int i_iFlags)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        (NULL == o_pBuffer) ||
        (0 == i_nBufferSize)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    PBYTE pbBuffer = o_pBuffer;

    SIZE_T nTotalNumOfBytesSent = 0;

    while (i_nBufferSize > nTotalNumOfBytesSent)
    {
        DWORD dwNumOfBytesToSend = (DWORD)min((i_nBufferSize - nTotalNumOfBytesSent), MAX_CHUNK_SIZE);

        DWORD dwNumOfBytesSent = 0;

        COMM_MANAGER_INNER_RETURN_VALUES nReturnValue = COMM_MANAGER_INNER_SUCCESS;

        nReturnValue = waitAndSend(i_pCommunicationManager, pbBuffer + nTotalNumOfBytesSent, dwNumOfBytesToSend, i_iFlags, dwNumOfBytesSent);
        if (COMM_MANAGER_INNER_SUCCESS != nReturnValue)
        {
            return nReturnValue;
        }

        nTotalNumOfBytesSent += dwNumOfBytesSent;
    }

    return COMM_MANAGER_INNER_SUCCESS;
}

static COMM_MANAGER_INNER_RETURN_VALUES encryptData(
    const BYTE* i_pbKey,
    const BYTE* i_pbPlainText,
    DWORD i_dwPlainTextLen,
    PBYTE* o_ppbCipherText,
    DWORD* o_pdwCipherTextLen)
{
    if (
        (NULL == i_pbKey) ||
        (NULL == i_pbPlainText) ||
        (0 == i_dwPlainTextLen) ||
        (NULL == o_ppbCipherText) ||
        (NULL == o_pdwCipherTextLen)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    DWORD dwStatus = 0;

    *o_ppbCipherText = NULL;
    *o_pdwCipherTextLen = 0;

    // Open AES provider
    BCRYPT_ALG_HANDLE hAlg = NULL;
    dwStatus = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (0 != dwStatus)
    {
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    COMM_MANAGER_INNER_RETURN_VALUES nReturnValue = COMM_MANAGER_INNER_SUCCESS;

    do
    {
        // Set ECB mode
        dwStatus = BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
            sizeof(BCRYPT_CHAIN_MODE_ECB),
            0);
        if (0 != dwStatus)
        {
            nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
            break;
        }

        // Generate key
        BCRYPT_KEY_HANDLE hKey = NULL;
        dwStatus = BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            NULL,
            0,
            (PUCHAR)i_pbKey,
            AES_KEY_SIZE,
            0);
        if (0 != dwStatus)
        {
            nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
            break;
        }

        do
        {
            // Get required ciphertext size
            DWORD dwCipherTextLen = 0;
            dwStatus = BCryptEncrypt(
                hKey,
                (PUCHAR)i_pbPlainText,
                i_dwPlainTextLen,
                NULL,
                NULL,   // No IV in ECB
                0,
                NULL,
                0,
                &dwCipherTextLen,
                BCRYPT_BLOCK_PADDING);
            if (0 != dwStatus)
            {
                nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
                break;
            }

            BYTE* pbOutput = (BYTE*)malloc(dwCipherTextLen);
            if (NULL == pbOutput)
            {
                nReturnValue = COMM_MANAGER_INNER_OUT_OF_MEMORY;
                break;
            }

            // Perform encryption
            dwStatus = BCryptEncrypt(
                hKey,
                (PUCHAR)i_pbPlainText,
                i_dwPlainTextLen,
                NULL,
                NULL,   // No IV
                0,
                pbOutput,
                dwCipherTextLen,
                &dwCipherTextLen,
                BCRYPT_BLOCK_PADDING);
            if (0 != dwStatus)
            {
                free(pbOutput);
                
                nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
                break;
            }

            *o_ppbCipherText = pbOutput;
            *o_pdwCipherTextLen = dwCipherTextLen;

        } while (FALSE);

        BCryptDestroyKey(hKey);

    } while (FALSE);

    BCryptCloseAlgorithmProvider(hAlg, 0);

    return nReturnValue;
}

static DWORD decryptData(
    const BYTE* i_pbKey,
    const BYTE* i_pbCipherText,
    DWORD i_dwCipherTextLen,
    PBYTE* o_ppbPlainText,
    DWORD* o_pdwPlainTextLen)
{
    if (
        (NULL == i_pbKey) ||
        (NULL == i_pbCipherText) ||
        (0 == i_dwCipherTextLen) ||
        (NULL == o_ppbPlainText) ||
        (NULL == o_pdwPlainTextLen)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }
    DWORD dwStatus = 0;

    *o_ppbPlainText = NULL;
    *o_pdwPlainTextLen = 0;

    // Open AES provider
    BCRYPT_ALG_HANDLE hAlg = NULL;
    dwStatus = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (0 != dwStatus)
    {
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    COMM_MANAGER_INNER_RETURN_VALUES nReturnValue = COMM_MANAGER_INNER_SUCCESS;

    do
    {
        // Set ECB mode
        dwStatus = BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
            sizeof(BCRYPT_CHAIN_MODE_ECB),
            0);
        if (0 != dwStatus)
        {
            nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
            break;
        }

        // Generate symmetric key
        BCRYPT_KEY_HANDLE hKey = NULL;
        dwStatus = BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            NULL,
            0,
            (PUCHAR)i_pbKey,
            AES_KEY_SIZE,
            0);
        if (0 != dwStatus)
        {
            nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
            break;
        }

        do
        {
            // Get required plaintext size
            DWORD dwPlainTextLen = 0;
            dwStatus = BCryptDecrypt(
                hKey,
                (PUCHAR)i_pbCipherText,
                i_dwCipherTextLen,
                NULL,
                NULL,   // No IV in ECB
                0,
                NULL,
                0,
                &dwPlainTextLen,
                BCRYPT_BLOCK_PADDING);
            if (0 != dwStatus)
            {
                nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
                break;
            }

            BYTE* pbOutput = (BYTE*)malloc(dwPlainTextLen);
            if (NULL == pbOutput)
            {
                nReturnValue = COMM_MANAGER_INNER_OUT_OF_MEMORY;
                break;
            }

            // Perform decryption
            dwStatus = BCryptDecrypt(
                hKey,
                (PUCHAR)i_pbCipherText,
                i_dwCipherTextLen,
                NULL,
                NULL,   // No IV
                0,
                pbOutput,
                dwPlainTextLen,
                &dwPlainTextLen,
                BCRYPT_BLOCK_PADDING);
            if (0 != dwStatus)
            {
                free(pbOutput);

                nReturnValue = COMM_MANAGER_INNER_GENERAL_ERROR;
                break;
            }

            *o_ppbPlainText = pbOutput;
            *o_pdwPlainTextLen = dwPlainTextLen;
        } while (FALSE);

        BCryptDestroyKey(hKey);

    } while (FALSE);

    BCryptCloseAlgorithmProvider(hAlg, 0);

    return nReturnValue;
}

static COMM_MANAGER_INNER_RETURN_VALUES sendEncryptedPacket(PCOMMUNICATION_MANAGER i_pCommunicationManager, const BYTE* i_pbData, DWORD i_dwDataLen)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        (NULL == i_pbData) ||
        (0 == i_dwDataLen)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    COMM_MANAGER_INNER_RETURN_VALUES nReturnValue = COMM_MANAGER_INNER_SUCCESS;

    do
    {
        nReturnValue = sendExact(i_pCommunicationManager->m_socket, (const char*)&i_dwDataLen, sizeof(DWORD), 0);
        if (COMM_MANAGER_INNER_SUCCESS != nReturnValue)
        {
            break;
        }

        nReturnValue = sendExact(i_pCommunicationManager->m_socket, i_pbData, i_dwDataLen, 0);
        if (COMM_MANAGER_INNER_SUCCESS != nReturnValue)
        {
            break;
        }
    } while (FALSE);

    return nReturnValue;
}

static COMM_MANAGER_INNER_RETURN_VALUES receiveEncryptedPacket(PCOMMUNICATION_MANAGER i_pCommunicationManager, PBYTE* o_ppbBuffer, DWORD* o_pdwBufferLen)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        (NULL == o_ppbBuffer) ||
        (0 == o_pdwBufferLen)
    )
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    DWORD dwPacketSize = 0;

    *o_ppbBuffer = NULL;
    *o_pdwBufferLen = 0;

    // Receive 4-byte big-endian length

    COMM_MANAGER_INNER_RETURN_VALUES nReturnValue = COMM_MANAGER_INNER_SUCCESS;

    nReturnValue = recvExact(
        i_pCommunicationManager,
        ((char*)&dwPacketSize),
        sizeof(DWORD),
        0);

    if (COMM_MANAGER_INNER_SUCCESS != nReturnValue)
    {
        return nReturnValue;
    }

    if (dwPacketSize == 0)
    {
        return COMM_MANAGER_INNER_PROTOCOL_ERROR;
    }

    // Allocate buffer
    BYTE* pbBuffer = (BYTE*)malloc(dwPacketSize);
    if (NULL == pbBuffer)
    {
        return COMM_MANAGER_INNER_OUT_OF_MEMORY;
    }

    nReturnValue = recvExact(
        i_pCommunicationManager,
        (char*)pbBuffer,
        dwPacketSize,
        0);

    if (COMM_MANAGER_INNER_SUCCESS != nReturnValue)
    {
        free(pbBuffer);
        return nReturnValue;
    }

    *o_ppbBuffer = pbBuffer;
    *o_pdwBufferLen = dwPacketSize;

    return COMM_MANAGER_INNER_SUCCESS;
}

static COMM_MANAGER_INNER_RETURN_VALUES eventsInit(PCOMMUNICATION_MANAGER i_pCommunicationManager)
{
    if (!communicationManagerSanityCheck(i_pCommunicationManager))
    {
        return COMM_MANAGER_INNER_INVALID_PARAMETERS;
    }

    HANDLE hTerminateEvent = CreateEventW(NULL, TRUE, FALSE, L"Terminate");
    if (NULL == hTerminateEvent)
    {
        return COMM_MANAGER_INNER_GENERAL_ERROR;
    }

    do
    {
        WSAEVENT hRecvEvent = WSACreateEvent();
        if (WSA_INVALID_EVENT == hRecvEvent)
        {
            break;
        }

        do
        {
            if (0 != WSAEventSelect(i_pCommunicationManager->m_socket, hRecvEvent, FD_READ))
            {
                break;
            }

            WSAEVENT hSendEvent = WSACreateEvent();
            if (WSA_INVALID_EVENT == hSendEvent)
            {
                break;
            }

            do
            {
                if (0 != WSAEventSelect(i_pCommunicationManager->m_socket, hSendEvent, FD_WRITE))
                {
                    break;
                }

                i_pCommunicationManager->m_hSocketRecvEvent = hRecvEvent;
                i_pCommunicationManager->m_hSocketSendEvent = hSendEvent;
                i_pCommunicationManager->m_hTerminateEvent = hTerminateEvent;

                return COMM_MANAGER_INNER_SUCCESS;

            } while (FALSE);

            WSACloseEvent(hSendEvent);

        } while (FALSE);

        WSACloseEvent(hRecvEvent);

    } while (FALSE);

    CloseHandle(hTerminateEvent);

    return COMM_MANAGER_INNER_GENERAL_ERROR;
}

static BOOLEAN communicationManagerSanityCheck(PCOMMUNICATION_MANAGER i_pCommunicationManager)
{
    if (NULL == i_pCommunicationManager)
    {
        return FALSE;
    }

    if (
        (INVALID_SOCKET == i_pCommunicationManager->m_socket) ||
        (WSA_INVALID_EVENT == i_pCommunicationManager->m_hSocketRecvEvent) ||
        (WSA_INVALID_EVENT == i_pCommunicationManager->m_hSocketSendEvent) ||
        (NULL == i_pCommunicationManager->m_hTerminateEvent)
    )
    {
        return FALSE;
    }

    return TRUE;
}

COMM_MANAGER_RETURN_VALUES CommunicationManager_ConnectToServer(const LPCWSTR i_wszHost, const LPCWSTR i_wszPort, PCOMMUNICATION_MANAGER o_pCommunicationManager) 
{
    if (
        (NULL == i_wszHost) ||
        (NULL == i_wszPort) ||
        (NULL == o_pCommunicationManager)
    )
    {
        return COMM_MANAGER_INVALID_PARAMETERS;
    }

    memset(o_pCommunicationManager, 0, sizeof(*o_pCommunicationManager));
    o_pCommunicationManager->m_socket = INVALID_SOCKET;

    if (COMM_MANAGER_INNER_SUCCESS != initializeWinsock())
    {
        return COMM_MANAGER_ERROR;
    }

    COMM_MANAGER_RETURN_VALUES nReturnValue = COMM_MANAGER_SUCCESS;

    do
    {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (INVALID_SOCKET == sock)
        {
            nReturnValue = COMM_MANAGER_ERROR;
            break;
        }

        do
        {
            ADDRINFOW inputAddr = { 0 };
            inputAddr.ai_family = AF_INET;
            inputAddr.ai_socktype = SOCK_STREAM;
            inputAddr.ai_protocol = IPPROTO_TCP;

            PADDRINFOW pResultAddr = NULL;
            if (0 != GetAddrInfoW(i_wszHost, i_wszPort, &inputAddr, &pResultAddr))
            {
                nReturnValue = COMM_MANAGER_ERROR;
                break;
            }

           do
           {
               if (SOCKET_ERROR == connect(sock, pResultAddr->ai_addr, (int)pResultAddr->ai_addrlen))
               {
                   nReturnValue = COMM_MANAGER_ERROR;
                   break;
               }

               if (COMM_MANAGER_INNER_SUCCESS != eventsInit(o_pCommunicationManager))
               {
                   nReturnValue = COMM_MANAGER_ERROR;
                   break;
               }

               FreeAddrInfoW(pResultAddr);

               o_pCommunicationManager->m_socket = sock;

               memset(o_pCommunicationManager->m_abAesKey, 0, AES_KEY_SIZE);
               memcpy(o_pCommunicationManager->m_abAesKey, KEY_TEXT, sizeof(KEY_TEXT));

               return COMM_MANAGER_SUCCESS;

           } while (FALSE);

           FreeAddrInfoW(pResultAddr);

        } while (FALSE);

        closesocket(sock);
        
    } while (FALSE);
    
    return nReturnValue;
}

COMM_MANAGER_RETURN_VALUES CommunicationManager_ReceiveCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, PCOMMAND o_pCommand)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager))  ||
        (NULL == o_pCommand)
    ) 
    {
        return COMM_MANAGER_INVALID_PARAMETERS;
    }

    o_pCommand->m_pbData = NULL;
    o_pCommand->m_dwCommandId = 0;
    o_pCommand->m_dwDataLength = 0;

    BYTE* pbEncryptedBuffer = NULL;
    DWORD dwEncryptedBufferLen = 0;


    COMM_MANAGER_INNER_RETURN_VALUES nInnerReturnValue = COMM_MANAGER_INNER_SUCCESS;
    nInnerReturnValue = receiveEncryptedPacket(i_pCommunicationManager, &pbEncryptedBuffer, &dwEncryptedBufferLen);
    if (COMM_MANAGER_INNER_TERMINATE != nInnerReturnValue)
    {
        return COMM_MANAGER_TERMINATE;
    }
    else if (COMM_MANAGER_INNER_SUCCESS != nInnerReturnValue)
    {
        return COMM_MANAGER_ERROR;
    }
    
    BYTE* pbDecryptedBuffer = NULL;
    DWORD dwDecryptedBufferLen = 0;

    nInnerReturnValue = decryptData(i_pCommunicationManager->m_abAesKey, pbEncryptedBuffer, dwEncryptedBufferLen, &pbDecryptedBuffer, &dwDecryptedBufferLen);

    free(pbEncryptedBuffer);

    if (COMM_MANAGER_INNER_SUCCESS != nInnerReturnValue)
    {
        return COMM_MANAGER_ERROR;
    }

    if (dwDecryptedBufferLen < sizeof(DWORD) * 2) 
    {
        return COMM_MANAGER_ERROR;
    }

    SIZE_T nOffset = 0;
    memcpy(&o_pCommand->m_dwCommandId, pbDecryptedBuffer + nOffset, sizeof(o_pCommand->m_dwCommandId));
    nOffset += sizeof(o_pCommand->m_dwCommandId);

    memcpy(&o_pCommand->m_dwDataLength, pbDecryptedBuffer + nOffset, sizeof(o_pCommand->m_dwDataLength));
    nOffset += sizeof(o_pCommand->m_dwDataLength);
    
    COMM_MANAGER_RETURN_VALUES nReturnValue = COMM_MANAGER_SUCCESS;

    do
    {
        if (nOffset + o_pCommand->m_dwDataLength > dwDecryptedBufferLen) {
            nReturnValue = COMM_MANAGER_ERROR;
            break;
        }

        if (o_pCommand->m_dwDataLength > 0) 
        {
            o_pCommand->m_pbData = malloc(o_pCommand->m_dwDataLength);
            if (NULL == o_pCommand->m_pbData) 
            {
                nReturnValue = COMM_MANAGER_ERROR;
                break;
            }

            memcpy(o_pCommand->m_pbData, pbDecryptedBuffer + nOffset, o_pCommand->m_dwDataLength);
        }
        else 
        {
            o_pCommand->m_pbData = NULL;
        }
    } while (FALSE);

    free(pbDecryptedBuffer);

    return nReturnValue;
}

COMM_MANAGER_RETURN_VALUES CommunicationManager_SendCommand(PCOMMUNICATION_MANAGER i_pCommunicationManager, DWORD i_dwCommandId, const BYTE* i_pbData, DWORD i_dwDataLength)
{
    if (
        (!communicationManagerSanityCheck(i_pCommunicationManager)) ||
        !(
            (NULL == i_pbData) &&
            (0 == i_dwDataLength)
         ) ||
        !(
            (NULL != i_pbData) &&
            (0 != i_dwDataLength)
         )
    )
    {
        return COMM_MANAGER_INVALID_PARAMETERS;
    }

    DWORD dwPacketSize = (sizeof(i_dwDataLength) * 2 + i_dwDataLength);

    BYTE* pbPacket = (BYTE*)malloc(dwPacketSize);
    if (NULL == pbPacket) 
    {
        return COMM_MANAGER_ERROR;
    }

    SIZE_T nOffset = 0;
    memcpy(pbPacket + nOffset, &i_dwCommandId, sizeof(i_dwCommandId));
    nOffset += sizeof(i_dwCommandId);

    memcpy(pbPacket + nOffset, &i_dwDataLength, sizeof(i_dwDataLength));
    nOffset += sizeof(i_dwDataLength);

    if (i_pbData && i_dwDataLength > 0) 
    {
        memcpy(pbPacket + nOffset, i_pbData, i_dwDataLength);
    }

    BYTE* pbEncryptedBuffer = NULL;
    DWORD dwEncryptedLen = 0;


    COMM_MANAGER_INNER_RETURN_VALUES nInnerReturnValue = COMM_MANAGER_INNER_SUCCESS;
    nInnerReturnValue = encryptData(i_pCommunicationManager->m_abAesKey, pbPacket, dwPacketSize, &pbEncryptedBuffer, &dwEncryptedLen);

    free(pbPacket);

    if (COMM_MANAGER_INNER_SUCCESS != nInnerReturnValue)
    {
        return COMM_MANAGER_ERROR;
    }

    nInnerReturnValue = sendEncryptedPacket(i_pCommunicationManager, pbEncryptedBuffer, dwEncryptedLen);

    free(pbEncryptedBuffer);

    if (COMM_MANAGER_INNER_TERMINATE != nInnerReturnValue)
    {
        return COMM_MANAGER_TERMINATE;
    }
    else if (COMM_MANAGER_INNER_SUCCESS != nInnerReturnValue)
    {
        return COMM_MANAGER_ERROR;
    }

    return COMM_MANAGER_SUCCESS;
}

VOID CommunicationManager_Disconnect(PCOMMUNICATION_MANAGER io_pCommunicationManager)
{
    if (
        (!g_bIsWSASetUp) ||
        (NULL == io_pCommunicationManager)
    )
    {
        return;
    }

    if (WSA_INVALID_EVENT != io_pCommunicationManager->m_hSocketRecvEvent)
    {
        WSACloseEvent(io_pCommunicationManager->m_hSocketRecvEvent);
        io_pCommunicationManager->m_hSocketRecvEvent = WSA_INVALID_EVENT;
    }

    if (WSA_INVALID_EVENT != io_pCommunicationManager->m_hSocketSendEvent)
    {
        WSACloseEvent(io_pCommunicationManager->m_hSocketSendEvent);
        io_pCommunicationManager->m_hSocketSendEvent = WSA_INVALID_EVENT;
    }

    if (NULL != io_pCommunicationManager->m_hTerminateEvent)
    {
        CloseHandle(io_pCommunicationManager->m_hTerminateEvent);
        io_pCommunicationManager->m_hTerminateEvent = NULL;
    }

    if (INVALID_SOCKET != io_pCommunicationManager->m_socket)
    {
        shutdown(io_pCommunicationManager->m_socket, SD_BOTH);
        closesocket(io_pCommunicationManager->m_socket);
        io_pCommunicationManager->m_socket = INVALID_SOCKET;
    }

    WSACleanup();
    memset(io_pCommunicationManager->m_abAesKey, 0, AES_KEY_SIZE);
}
