#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define PORT_NAME L"\\RansomwareFilterPort"
#define MAX_MSG_SIZE 1024
#define HEURISTIC_WINDOW_MS 5000 // 5 segundos
#define MAX_FILES_THRESHOLD 5    // Limite mais sensível
#define MAX_FILE_SIZE_MB 5       // Tamanho máximo para monitoramento intensivo

// Estrutura para rastrear atividade de processos
typedef struct _PROCESS_ACTIVITY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    LARGE_INTEGER LastActivityTime;
    ULONG FileCount;
    BOOLEAN IsSuspicious;
} PROCESS_ACTIVITY, * PPROCESS_ACTIVITY;

// Estrutura de mensagem para comunicação com user-mode
typedef struct _KERNEL_TO_USER_MSG {
    ULONG ProcessId;
    WCHAR ProcessName[32];
    WCHAR FileName[260];
    ULONG OperationType; // 0=Write, 1=Create, 2=SetInfo
    BOOLEAN IsSuspicious;
    BOOLEAN IsFastWrite;
    BOOLEAN IsCriticalFile;
    LARGE_INTEGER Timestamp;
} KERNEL_TO_USER_MSG, * PKERNEL_TO_USER_MSG;

// Variáveis globais
PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
LIST_ENTRY gActivityList;
KSPIN_LOCK gActivityLock;

// Extensões suspeitas
const WCHAR* SuspiciousExtensions[] = {
    L".encrypted", L".locky", L".crypto", L".locked",
    L".wanna", L".aesir", L".vault", L".crypt",
    L".rzp", L".locked", L".cryptolocker", L".tesla"
};

// Diretórios críticos
const WCHAR* CriticalDirectories[] = {
    L"\\Documents\\", L"\\Desktop\\", L"\\Pictures\\",
    L"\\Downloads\\", L"\\Teste\\", L"\\OneDrive\\"
};

// Protótipos de função
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
NTSTATUS ConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie);
VOID DisconnectNotify(PVOID ConnectionCookie);
NTSTATUS MessageNotify(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength);
BOOLEAN IsSuspiciousOperation(PFLT_CALLBACK_DATA Data, PKERNEL_TO_USER_MSG msg);
VOID UpdateProcessActivity(ULONG ProcessId, BOOLEAN isSuspicious);
VOID CleanupOldActivities();
BOOLEAN IsCriticalFile(PWSTR FileName);
BOOLEAN IsFastOperation(PFLT_CALLBACK_DATA Data);

// Callbacks de operação
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_WRITE, 0, PreOperationCallback, NULL },
    { IRP_MJ_CREATE, 0, PreOperationCallback, NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreOperationCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

// Registro do filtro
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd;

    UNREFERENCED_PARAMETER(RegistryPath);

    // Configuração inicial
    InitializeListHead(&gActivityList);
    KeInitializeSpinLock(&gActivityLock);

    // Cria descritor de segurança
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Falha em FltBuildDefaultSecurityDescriptor: 0x%X\n", status);
        return status;
    }

    // Configura porta de comunicação
    RtlInitUnicodeString(&portName, PORT_NAME);
    InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

    // Registra o filtro
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Falha em FltRegisterFilter: 0x%X\n", status);
        FltFreeSecurityDescriptor(sd);
        return status;
    }

    // Cria porta de comunicação
    status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &oa, NULL, ConnectNotify, DisconnectNotify, MessageNotify, 1);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Falha em FltCreateCommunicationPort: 0x%X\n", status);
        FltUnregisterFilter(gFilterHandle);
        FltFreeSecurityDescriptor(sd);
        return status;
    }

    // Inicia o filtro
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Falha em FltStartFiltering: 0x%X\n", status);
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilterHandle);
        FltFreeSecurityDescriptor(sd);
        return status;
    }

    FltFreeSecurityDescriptor(sd);
    DbgPrint("RansomwareFilterDriver: Driver carregado com sucesso!\n");
    return STATUS_SUCCESS;
}

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    KIRQL oldIrql;
    PPROCESS_ACTIVITY entry, nextEntry;

    // Limpa a lista de atividades
    KeAcquireSpinLock(&gActivityLock, &oldIrql);
    entry = (PPROCESS_ACTIVITY)gActivityList.Flink;
    while (entry != (PPROCESS_ACTIVITY)&gActivityList) {
        nextEntry = (PPROCESS_ACTIVITY)entry->ListEntry.Flink;
        RemoveEntryList(&entry->ListEntry);
        ExFreePoolWithTag(entry, 'RACT');
        entry = nextEntry;
    }
    KeReleaseSpinLock(&gActivityLock, oldIrql);

    // Fecha a porta e desregistra o filtro
    if (gServerPort) FltCloseCommunicationPort(gServerPort);
    if (gFilterHandle) FltUnregisterFilter(gFilterHandle);

    DbgPrint("RansomwareFilterDriver: Driver descarregado.\n");
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS PreOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!gClientPort) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    KERNEL_TO_USER_MSG msg = { 0 };
    PEPROCESS process = IoThreadToProcess(Data->Thread);
    msg.ProcessId = process ? (ULONG)(ULONG_PTR)PsGetProcessId(process) : 0;

    if (msg.ProcessId == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Obtém informações do arquivo
    PFLT_FILE_NAME_INFORMATION nameInfo;
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        wcsncpy_s(msg.FileName, 260, nameInfo->Name.Buffer, min(nameInfo->Name.Length / sizeof(WCHAR), 259));
        FltReleaseFileNameInformation(nameInfo);
    }
    else {
        wcsncpy_s(msg.FileName, 260, L"Unknown", 7);
    }

    // Obtém nome do processo
    PUNICODE_STRING pUniName = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)msg.ProcessId, &process))) {
        if (NT_SUCCESS(SeLocateProcessImageName(process, &pUniName))) {
            if (pUniName && pUniName->Buffer) {
                wcsncpy_s(msg.ProcessName, 32, pUniName->Buffer, min(pUniName->Length / sizeof(WCHAR), 31));
                ExFreePool(pUniName);
            }
        }
        ObDereferenceObject(process);
    }

    // Determina tipo de operação
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_WRITE:
        msg.OperationType = 0;
        msg.IsFastWrite = IsFastOperation(Data);
        break;
    case IRP_MJ_CREATE:
        msg.OperationType = 1;
        msg.IsFastWrite = FALSE;
        break;
    case IRP_MJ_SET_INFORMATION:
        msg.OperationType = 2;
        msg.IsFastWrite = FALSE;
        break;
    }

    // Verifica se é uma operação suspeita
    msg.IsCriticalFile = IsCriticalFile(msg.FileName);
    msg.IsSuspicious = IsSuspiciousOperation(Data, &msg);

    // Se for suspeita, envia mensagem para user-mode
    if (msg.IsSuspicious) {
        KeQuerySystemTime(&msg.Timestamp);
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100 * 10000; // 1 segundo

        NTSTATUS status = FltSendMessage(gFilterHandle, &gClientPort, &msg, sizeof(msg), NULL, NULL, &timeout);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Falha ao enviar mensagem (PID %d): 0x%X\n", msg.ProcessId, status);
        }
    }

    // Atualiza atividade do processo
    UpdateProcessActivity(msg.ProcessId, msg.IsSuspicious);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS ConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    gClientPort = ClientPort;
    DbgPrint("Conexão com aplicativo estabelecida.\n");
    return STATUS_SUCCESS;
}

VOID DisconnectNotify(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    gClientPort = NULL;
    DbgPrint("Conexão com aplicativo perdida.\n");
}

NTSTATUS MessageNotify(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    return STATUS_SUCCESS;
}

BOOLEAN IsSuspiciousOperation(PFLT_CALLBACK_DATA Data, PKERNEL_TO_USER_MSG msg)
{
    // Verifica extensões suspeitas
    for (int i = 0; i < RTL_NUMBER_OF(SuspiciousExtensions); i++) {
        if (wcsstr(msg->FileName, SuspiciousExtensions[i])) {
            return TRUE;
        }
    }

    // Verifica diretórios críticos
    for (int i = 0; i < RTL_NUMBER_OF(CriticalDirectories); i++) {
        if (wcsstr(msg->FileName, CriticalDirectories[i])) {
            return TRUE;
        }
    }

    // Verifica renomeações suspeitas
    if (msg->OperationType == 2 && Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
        return TRUE;
    }

    // Verifica operações rápidas em arquivos grandes
    if (msg->IsFastWrite) {
        return TRUE;
    }

    return FALSE;
}

VOID UpdateProcessActivity(ULONG ProcessId, BOOLEAN isSuspicious)
{
    KIRQL oldIrql;
    PPROCESS_ACTIVITY activity;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);
    KeAcquireSpinLock(&gActivityLock, &oldIrql);

    // Busca atividade existente
    for (PLIST_ENTRY link = gActivityList.Flink; link != &gActivityList; link = link->Flink) {
        activity = CONTAINING_RECORD(link, PROCESS_ACTIVITY, ListEntry);
        if (activity->ProcessId == ProcessId) {
            activity->LastActivityTime = currentTime;
            activity->FileCount++;
            if (isSuspicious) activity->IsSuspicious = TRUE;
            KeReleaseSpinLock(&gActivityLock, oldIrql);
            return;
        }
    }

    // Cria nova entrada de atividade usando ExAllocatePool2
    activity = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_ACTIVITY), 'RACT');
    if (activity) {
        activity->ProcessId = ProcessId;
        activity->LastActivityTime = currentTime;
        activity->FileCount = 1;
        activity->IsSuspicious = isSuspicious;
        InsertTailList(&gActivityList, &activity->ListEntry);
    }

    KeReleaseSpinLock(&gActivityLock, oldIrql);
    CleanupOldActivities();
}

VOID CleanupOldActivities()
{
    KIRQL oldIrql;
    PPROCESS_ACTIVITY activity;
    LARGE_INTEGER currentTime;

    KeQuerySystemTime(&currentTime);
    KeAcquireSpinLock(&gActivityLock, &oldIrql);

    for (PLIST_ENTRY link = gActivityList.Flink; link != &gActivityList;) {
        activity = CONTAINING_RECORD(link, PROCESS_ACTIVITY, ListEntry);
        PLIST_ENTRY nextLink = link->Flink;

        LARGE_INTEGER timeDiff;
        timeDiff.QuadPart = currentTime.QuadPart - activity->LastActivityTime.QuadPart;

        // Remove atividades antigas (mais de 10 segundos)
        if (timeDiff.QuadPart > -100000000) {
            RemoveEntryList(&activity->ListEntry);
            ExFreePoolWithTag(activity, 'RACT');
        }

        link = nextLink;
    }

    KeReleaseSpinLock(&gActivityLock, oldIrql);
}

BOOLEAN IsCriticalFile(PWSTR FileName)
{
    // Verifica extensões críticas
    for (int i = 0; i < RTL_NUMBER_OF(SuspiciousExtensions); i++) {
        if (wcsstr(FileName, SuspiciousExtensions[i])) {
            return TRUE;
        }
    }

    // Verifica diretórios críticos
    for (int i = 0; i < RTL_NUMBER_OF(CriticalDirectories); i++) {
        if (wcsstr(FileName, CriticalDirectories[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN IsFastOperation(PFLT_CALLBACK_DATA Data)
{
    // Verifica escrita rápida
    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        return (Data->Iopb->Parameters.Write.Length > MAX_FILE_SIZE_MB * 1024 * 1024);
    }

    return FALSE;
}
