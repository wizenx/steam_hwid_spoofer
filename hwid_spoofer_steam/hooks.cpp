#include "hooks.h"

#include <Windows.h>
#include <winternl.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <algorithm>

#include <minhook/MinHook.h>
#include "patterns.h"
#include "utils.h"
#include "xorstr.hpp"

static session_profile session;

static hooks::get_machine_guid_fn orig_get_machine_guid = nullptr;
static hooks::get_mac_address_fn orig_get_mac_address = nullptr;
static hooks::get_mac_wmi_fn orig_get_mac_address_two = nullptr;
static hooks::get_disk_serial_fn orig_get_disk_serial = nullptr;


static hooks::get_local_hostname_fn orig_get_local_hostname = nullptr;

static PVOID g_dll_notify_cookie = nullptr;
static bool steam_hooks_placed = false;
static bool tier0_hooks_placed = false;

bool install_hook(LPVOID target, LPVOID detour, LPVOID* original, const char* success_message, const char* error_message)
{
    if (target == nullptr)
    {
        utils::logdbg("[-] %s", error_message);
        return false;
    }

    if (MH_CreateHook(target, detour, original) != MH_OK)
    {
        utils::logdbg("[-] failed to create hook: %s", error_message);
        return false;
    }

    if (MH_EnableHook(target) != MH_OK)
    {
        utils::logdbg("[-] failed to enable hook: %s", error_message);
        return false;
    }

    utils::logdbg("[+] %s", success_message);
    return true;
}

char __fastcall hook_get_machine_guid(unsigned char* buf, DWORD size)
{
    const char result = orig_get_machine_guid(buf, size);
    if (result != 0)
    {
        const std::string old = reinterpret_cast<const char*>(buf);
        strcpy_s(reinterpret_cast<char*>(buf), size, session.machine_guid.c_str( ));
        utils::logdbg("[*] guid: %s -> %s", old.c_str( ), session.machine_guid.c_str( ));
    }
    return result;
}

DWORD __fastcall hook_get_mac_address(unsigned long long* a1)
{
    const DWORD result = orig_get_mac_address(a1);

    if (a1 != nullptr)
    {
        const std::string old_mac_str = utils::fmt_mac(a1);

        int bytes[6];
        if (std::sscanf(session.mac_address.c_str( ), "%02x-%02x-%02x-%02x-%02x-%02x",
            &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6)
        {
            unsigned char mac_bin[6];
            for (int i = 0; i < 6; ++i)
                mac_bin[i] = static_cast<unsigned char>(bytes[i]);

            *a1 = 0; 
            std::memcpy(a1, mac_bin, 6); 

            utils::logdbg("[*] mac 1: %s -> %s",
                old_mac_str.c_str( ),
                session.mac_address.c_str( ));
        }
    }
    return result;
}

__int64 __fastcall hook_get_mac_two(unsigned __int64* a1, char a2)
{
    __int64 result = orig_get_mac_address_two(a1, a2);

    if (a1 != nullptr)
    {
        const std::string old_mac_str = utils::fmt_mac(a1);

        int bytes[6];
        if (std::sscanf(session.mac_address.c_str( ), "%02x-%02x-%02x-%02x-%02x-%02x",
            &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6)
        {
            unsigned char mac_bin[6];
            for (int i = 0; i < 6; ++i)
                mac_bin[i] = static_cast<unsigned char>(bytes[i]);

            *a1 = 0;
            std::memcpy(a1, mac_bin, 6);

            utils::logdbg("[*] mac 2: %s -> %s",
                old_mac_str.c_str( ),
                session.mac_address.c_str( ));
        }
    }
    return result;
}

bool __fastcall hook_get_disk_serial(unsigned char* buf, int a2)
{
    const bool result = orig_get_disk_serial(buf, a2);
    if (result)
    {
        const std::string old = reinterpret_cast<const char*>(buf);
        strcpy_s(reinterpret_cast<char*>(buf), 256, session.disk_serial.c_str( ));
        utils::logdbg("[*] disk: %s -> %s", old.c_str( ), session.disk_serial.c_str( ));

        if (HANDLE h = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            MessageBoxA(nullptr, "spoofed last stage - so i think all is spoofed.",
                xorstr_("github.com/wizenx"), MB_OK | MB_ICONINFORMATION);
            return 0;
            }, nullptr, 0, nullptr))
        {
            CloseHandle(h);
        }
    }
    return result;
}

const char* __fastcall hook_get_local_hostname()
{
    const char* o_tier0_buffer = orig_get_local_hostname( );

    std::string real_name = "unknown";
    if (o_tier0_buffer != nullptr && o_tier0_buffer[0] != '\0')
    {
        real_name = o_tier0_buffer;
    }

    utils::logdbg("[*] getlocalhostname: %s -> %s",
        real_name.c_str( ),
        session.pc_name.c_str( )
    );

    return session.pc_name.c_str( );
}

void setup_steam_hooks(HMODULE steamclient_handle)
{
    utils::logdbg("[*] steamclient64.dll found. hooks processing");

    const uintptr_t machine_guid_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::machine_guid_call));
    const uintptr_t mac_address_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::mac_address_call));
    const uintptr_t mac_address_target_two = utils::get_absolute_address(
		utils::find_pattern(xorstr_("steamclient64.dll"), patterns::mac_address_call_2));
    const uintptr_t disk_serial_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::disk_serial_call));


    install_hook(reinterpret_cast<LPVOID>(machine_guid_target), reinterpret_cast<LPVOID>(&hook_get_machine_guid), reinterpret_cast<LPVOID*>(&orig_get_machine_guid), "machine guid hook installed.", "could not resolve machine guid target.");
    install_hook(reinterpret_cast<LPVOID>(mac_address_target), reinterpret_cast<LPVOID>(&hook_get_mac_address), reinterpret_cast<LPVOID*>(&orig_get_mac_address), "mac address hook installed.", "could not resolve mac address target.");
    install_hook(reinterpret_cast<LPVOID>(mac_address_target_two), reinterpret_cast<LPVOID>(&hook_get_mac_two), reinterpret_cast<LPVOID*>(&orig_get_mac_address_two), "mac address 2 hook installed.", "could not resolve mac address 2 target.");
    install_hook(reinterpret_cast<LPVOID>(disk_serial_target), reinterpret_cast<LPVOID>(&hook_get_disk_serial), reinterpret_cast<LPVOID*>(&orig_get_disk_serial), "disk serial hook installed.", "could not resolve disk serial target.");
    
}

void setup_tier0_hooks(HMODULE tier0_handle)
{
    utils::logdbg("[*] tier0_s64.dll found. hooks processing");

    LPVOID local_hostname_target = reinterpret_cast<LPVOID>(
        GetProcAddress(tier0_handle, "GetLocalHostname")
        );

    install_hook(
        local_hostname_target,
        reinterpret_cast<LPVOID>(&hook_get_local_hostname),
        reinterpret_cast<LPVOID*>(&orig_get_local_hostname),
        "pc name hook installed",
        "could not find GetLocalHostname export"
    );
}

void CALLBACK dll_notification_callback(ULONG reason, const LDR_DLL_NOTIFICATION_DATA* data, PVOID context)
{
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;

    if (!data || !data->Loaded.BaseDllName || !data->Loaded.BaseDllName->Buffer)
        return;

    std::wstring dll_name(
        data->Loaded.BaseDllName->Buffer,
        data->Loaded.BaseDllName->Length / sizeof(wchar_t)
    );

    dll_name = utils::to_lower(dll_name);

    if (!tier0_hooks_placed && dll_name == xorstr_(L"tier0_s64.dll"))
    {
        tier0_hooks_placed = true;
        HMODULE tier0 = reinterpret_cast<HMODULE>(data->Loaded.DllBase);
        setup_tier0_hooks(tier0);
    }

    if (!steam_hooks_placed && dll_name == xorstr_(L"steamclient64.dll"))
    {
        steam_hooks_placed = true;
        HMODULE steamclient = reinterpret_cast<HMODULE>(data->Loaded.DllBase);
        setup_steam_hooks(steamclient);
    }
}

void hooks::set_session_profile(const session_profile& profile)
{
    session = profile;
}

bool hooks::init( )
{
    utils::logdbg("[*] initializing hooks...");

    if (MH_Initialize( ) != MH_OK)
    {
        utils::logdbg("[-] hook init failed.");
        return false;
    }

    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        utils::logdbg("[-] failed to get ntdll.dll");
        return false;
    }

    auto LdrRegisterDllNotification = reinterpret_cast<LdrRegisterDllNotification_t>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification")
        );

    if (!LdrRegisterDllNotification)
    {
        utils::logdbg("[-] failed to resolve LdrRegisterDllNotification.");
        return false;
    }

    NTSTATUS status = LdrRegisterDllNotification(
        0,
        dll_notification_callback,
        nullptr,
        &g_dll_notify_cookie
    );

    if (status >= 0)
    {
        utils::logdbg("[+] LdrRegisterDllNotification success!");
        return true;
    }

    utils::logdbg("[-] LdrRegisterDllNotification failed.");
    return false;
}