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
static hooks::get_disk_serial_fn orig_get_disk_serial = nullptr;

static hooks::get_local_hostname_fn orig_get_local_hostname = nullptr;

static PVOID g_dll_notify_cookie = nullptr;
static bool steam_hooks_placed = false;
static bool tier0_hooks_placed = false;

static std::wstring to_lower(std::wstring s)
{
    std::transform(s.begin( ), s.end( ), s.begin( ),
        [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

std::string fmt_mac(const void* ptr)
{
    if (ptr == nullptr) return "null";

    const auto* mac = reinterpret_cast<const unsigned char*>(ptr);
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X-%02X-%02X-%02X-%02X-%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return buf;
}

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
        char* buf = reinterpret_cast<char*>(a1);
        const std::string old = fmt_mac(a1);
        strcpy_s(buf, 256, session.mac_address.c_str( ));
        utils::logdbg("[*] mac: %s -> %s", old.c_str( ), session.mac_address.c_str( ));
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
    const uintptr_t disk_serial_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::disk_serial_call));

    install_hook(reinterpret_cast<LPVOID>(machine_guid_target), reinterpret_cast<LPVOID>(&hook_get_machine_guid), reinterpret_cast<LPVOID*>(&orig_get_machine_guid), "machine guid hook installed.", "could not resolve machine guid target.");
    install_hook(reinterpret_cast<LPVOID>(mac_address_target), reinterpret_cast<LPVOID>(&hook_get_mac_address), reinterpret_cast<LPVOID*>(&orig_get_mac_address), "mac address hook installed.", "could not resolve mac address target.");
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

    dll_name = to_lower(dll_name);

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