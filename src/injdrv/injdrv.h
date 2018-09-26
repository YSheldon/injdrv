#pragma once
#include <ntddk.h>

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _INJ_HOOK_INFO
{
  LIST_ENTRY  ListEntry;

  //
  // Process ID of the hooked process.
  //
  HANDLE      ProcessId;

  //
  // Combination of INJ_SYSTEM_DLL flags indicating
  // which DLLs has been already loaded into this
  // process.
  //
  ULONG       LoadedDlls;

  //
  // If true, the hook has been already installed.
  //
  BOOLEAN     HookInstalled;

  //
  // If true, trigger of the queued user APC will be
  // immediately forced upon next kernel->user transition.
  //
  BOOLEAN     ForceUserApc;

  //
  // Address of LdrLoadDll routine within 32-bit ntdll.dll.
  //
  PVOID       LdrLoadDllX86;

#if defined(_M_AMD64)
  //
  // Address of LdrLoadDll routine within 64-bit ntdll.dll.
  //
  PVOID       LdrLoadDllX64;

  //
  // Address of Wow64ApcRoutine within wow64.dll.
  //
  PVOID       Wow64ApcRoutine;

  //
  // If true, 32-bit DLL will be injected into Wow64
  // processes.  If false, 64-bit DLL will be injected
  // into Wow64 processes.
  //
  BOOLEAN     UseWow64Injection;
#endif
} INJ_HOOK_INFO, *PINJ_HOOK_INFO;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjInitialize(
  _In_ PUNICODE_STRING HookDllPathX86,
  _In_ PUNICODE_STRING HookDllPathX64,
  _In_ BOOLEAN UseWow64Injection
  );

VOID
NTAPI
InjDestroy(
  VOID
  );

NTSTATUS
NTAPI
InjCreateHookInfo(
  _In_ HANDLE ProcessId
  );

VOID
NTAPI
InjRemoveHookInfo(
  _In_ HANDLE ProcessId
  );

PINJ_HOOK_INFO
NTAPI
InjFindHookInfo(
  _In_ HANDLE ProcessId
  );

BOOLEAN
NTAPI
InjCanInject(
  _In_ PINJ_HOOK_INFO HookInfo
  );

NTSTATUS
NTAPI
InjInject(
  _In_ PINJ_HOOK_INFO HookInfo
  );
