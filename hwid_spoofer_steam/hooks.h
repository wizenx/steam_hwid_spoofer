#pragma once

#include <Windows.h>
#include <winternl.h>

#include "profile.h"

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    const UNICODE_STRING* FullDllName;
    const UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    const LDR_DLL_NOTIFICATION_DATA* NotificationData,
    PVOID Context
    );

typedef NTSTATUS(NTAPI* LdrRegisterDllNotification_t)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID* Cookie
    );

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1


namespace hooks
{

	using get_machine_guid_fn = char(__fastcall*)(unsigned char* buf, DWORD size);
	using get_mac_address_fn = DWORD(__fastcall*)(unsigned long long* a1);
	using get_disk_serial_fn = bool(__fastcall*)(unsigned char* buf, int a2);
	using load_library_exw_fn = HMODULE(WINAPI*)(LPCWSTR name, HANDLE file, DWORD flags);
	
	using get_local_hostname_fn = const char* (__fastcall*)();

	void set_session_profile(const session_profile& profile);
	bool init();
}