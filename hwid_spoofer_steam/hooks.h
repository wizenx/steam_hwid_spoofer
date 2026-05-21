#pragma once

#include <Windows.h>

#include "profile.h"

namespace hooks
{
	using get_machine_guid_fn = char(__fastcall*)(unsigned char* buf, DWORD size);
	using get_mac_address_fn = DWORD(__fastcall*)(unsigned long long* a1);
	using get_disk_serial_fn = bool(__fastcall*)(unsigned char* buf, int a2);
	using load_library_exw_fn = HMODULE(WINAPI*)(LPCWSTR name, HANDLE file, DWORD flags);

	void set_session_profile(const session_profile& profile);
	bool init();
}