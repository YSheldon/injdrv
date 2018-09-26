#include <windows.h>
#include <detours.h>

#define EventActivityIdControl  EtwEventActivityIdControl
#define EventEnabled            EtwEventEnabled
#define EventProviderEnabled    EtwEventProviderEnabled
#define EventRegister           EtwEventRegister
#define EventSetInformation     EtwEventSetInformation
#define EventUnregister         EtwEventUnregister
#define EventWrite              EtwEventWrite
#define EventWriteEndScenario   EtwEventWriteEndScenario
#define EventWriteEx            EtwEventWriteEx
#define EventWriteStartScenario EtwEventWriteStartScenario
#define EventWriteString        EtwEventWriteString
#define EventWriteTransfer      EtwEventWriteTransfer

#include <TraceLoggingProvider.h>

//
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//

TRACELOGGING_DECLARE_PROVIDER(provider);
TRACELOGGING_DEFINE_PROVIDER(
  provider, "InjDllProvider",
  (0xa4b4ba50, 0xa667, 0x43f5, 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5)
);

#define NtCurrentProcess()        ((HANDLE)(LONG_PTR)-1)
#define ZwCurrentProcess()        NtCurrentProcess()
#define NtCurrentThread()         ((HANDLE)(LONG_PTR)-2)
#define ZwCurrentThread()         NtCurrentThread()

typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation,
  SystemProcessorInformation,
  SystemPerformanceInformation,
  SystemTimeOfDayInformation,
  SystemPathInformation,
  SystemProcessInformation,
  SystemCallCountInformation,
  SystemDeviceInformation,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI * fnNtQuerySystemInformation)(
  _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
  _In_ ULONG SystemInformationLength,
  _Out_opt_ PULONG ReturnLength
  );

inline fnNtQuerySystemInformation OrigNtQuerySystemInformation;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
  _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
  _In_ ULONG SystemInformationLength,
  _Out_opt_ PULONG ReturnLength
  );

EXTERN_C
NTSTATUS
NTAPI
HookNtQuerySystemInformation(
  _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
  _In_ ULONG SystemInformationLength,
  _Out_opt_ PULONG ReturnLength
  )
{
  __debugbreak();
  TraceLoggingWrite(provider,
    "MessageEvent",
    TraceLoggingValue(ULONG(SystemInformationClass), "SystemInformationClass"),
    TraceLoggingValue(ULONG_PTR(SystemInformation), "SystemInformation"),
    TraceLoggingValue(SystemInformationLength, "SystemInformationLength"));

  return OrigNtQuerySystemInformation(SystemInformationClass,
                                      SystemInformation,
                                      SystemInformationLength,
                                      ReturnLength);
}

EXTERN_C
BOOL
WINAPI
NtDllMain(
  _In_ HINSTANCE hModule,
  _In_ DWORD dwReason,
  _In_ LPVOID lpvReserved
  )
{
  switch (dwReason)
  {
    case DLL_PROCESS_ATTACH:
      __debugbreak();
      TraceLoggingRegister(provider);

      OrigNtQuerySystemInformation = NtQuerySystemInformation;

      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());
      DetourAttach((PVOID*)&OrigNtQuerySystemInformation, HookNtQuerySystemInformation);
      DetourTransactionCommit();
      break;

    case DLL_PROCESS_DETACH:
      DetourTransactionBegin();
      DetourUpdateThread(NtCurrentThread());
      DetourDetach((PVOID*)&OrigNtQuerySystemInformation, HookNtQuerySystemInformation);
      DetourTransactionCommit();
      break;

    case DLL_THREAD_ATTACH:

      break;

    case DLL_THREAD_DETACH:

      break;
  }

  return TRUE;
}
