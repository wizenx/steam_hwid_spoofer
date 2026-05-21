#include "hooks.h"

#include <Windows.h>

#include <cstdio>
#include <cstring>

#include <minhook/MinHook.h>
#include "patterns.h"
#include "utils.h"
#include "xorstr.hpp"

static session_profile session;

static hooks::get_machine_guid_fn orig_get_machine_guid = nullptr;
static hooks::get_mac_address_fn orig_get_mac_address = nullptr;
static hooks::get_disk_serial_fn orig_get_disk_serial = nullptr;
static hooks::load_library_exw_fn orig_load_library_exw = nullptr;

static bool steam_hooks_placed = false;

std::string fmt_mac(const void* ptr)
{
    if (ptr == nullptr)
    {
        return "null";
    }

    const auto* mac = reinterpret_cast<const unsigned char*>(ptr);
    char buf[18];
    std::snprintf(
        buf,
        sizeof(buf),
        "%02X-%02X-%02X-%02X-%02X-%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]);

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
        strcpy_s(reinterpret_cast<char*>(buf), size, session.machine_guid.c_str());

        utils::logdbg("[*] guid: %s -> %s", old.c_str(), session.machine_guid.c_str());
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
        strcpy_s(buf, 256, session.mac_address.c_str());

        utils::logdbg("[*] mac: %s -> %s", old.c_str(), session.mac_address.c_str());
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

        if (HANDLE h = CreateThread(
            nullptr,
            0,
            [](LPVOID) -> DWORD
            {
                MessageBoxA(
                    nullptr,
                    "spoofed last stage - so i think all is spoofed.",
                    xorstr_("github.com/wizenx"),
                    MB_OK | MB_ICONINFORMATION
                );
                return 0;
            },
            nullptr,
            0,
            nullptr
        ))
        {
            CloseHandle(h);
        }
    }

    return result;
}

void setup_steam_hooks()
{
    utils::logdbg("[*] module found. hooks processing");

    const uintptr_t machine_guid_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::machine_guid_call));
    const uintptr_t mac_address_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::mac_address_call));
    const uintptr_t disk_serial_target = utils::get_absolute_address(
        utils::find_pattern(xorstr_("steamclient64.dll"), patterns::disk_serial_call));

    const bool machine_guid_ok = install_hook(
        reinterpret_cast<LPVOID>(machine_guid_target),
        reinterpret_cast<LPVOID>(&hook_get_machine_guid),
        reinterpret_cast<LPVOID*>(&orig_get_machine_guid),
        "machine guid hook installed.",
        "could not resolve machine guid target.");

    const bool mac_address_ok = install_hook(
        reinterpret_cast<LPVOID>(mac_address_target),
        reinterpret_cast<LPVOID>(&hook_get_mac_address),
        reinterpret_cast<LPVOID*>(&orig_get_mac_address),
        "mac address hook installed.",
        "could not resolve mac address target.");

    const bool disk_serial_ok = install_hook(
        reinterpret_cast<LPVOID>(disk_serial_target),
        reinterpret_cast<LPVOID>(&hook_get_disk_serial),
        reinterpret_cast<LPVOID*>(&orig_get_disk_serial),
        "disk serial hook installed.",
        "could not resolve disk serial target.");

    if (machine_guid_ok && mac_address_ok && disk_serial_ok)
    {
       // MessageBoxA(nullptr, "hooks installed", xorstr_("github.com/wizenx"), MB_OK | MB_ICONINFORMATION);
    }
}

HMODULE WINAPI hook_load_library_exw(LPCWSTR name, HANDLE file, DWORD flags)
{
    HMODULE loaded_module = orig_load_library_exw(name, file, flags);

    if (loaded_module != nullptr &&
        !steam_hooks_placed &&
        name != nullptr &&
        wcsstr(name, xorstr_(L"steamclient64.dll")) != nullptr)
    {
        steam_hooks_placed = true;
        setup_steam_hooks();
    }

    return loaded_module;
}

void hooks::set_session_profile(const session_profile& profile)
{
    session = profile;
}

bool hooks::init()
{
    utils::logdbg("[*] initializing hooks...");

    if (MH_Initialize() != MH_OK)
    {
        utils::logdbg("[-] hook init failed.");
        return false;
    }

    HMODULE kernel_module = GetModuleHandleA("kernelbase.dll");
    if (kernel_module == nullptr)
    {
        kernel_module = GetModuleHandleA("kernel32.dll");
    }

    if (kernel_module == nullptr)
    {
        utils::logdbg("[-] failed to locate kernel32.dll");
        return false;
    }

    LPVOID load_library_addr = reinterpret_cast<LPVOID>(GetProcAddress(kernel_module, "LoadLibraryExW"));
    if (load_library_addr == nullptr)
    {
        utils::logdbg("[-] failed to resolve LoadLibraryExW");
        return false;
    }

    return install_hook(
        load_library_addr,
        reinterpret_cast<LPVOID>(&hook_load_library_exw),
        reinterpret_cast<LPVOID*>(&orig_load_library_exw),
        xorstr_("waiting for steamclient64.dll..."),
        "failed to set LoadLibraryExW hook.");
}
