#include <Windows.h>

#include "hooks.h"
#include "profile.h"
#include "utils.h"

#include "xorstr.hpp"

DWORD WINAPI MainThread(LPVOID)
{
    utils::initconsole();

    const session_profile profile = utils::generate_session_profile();
    utils::logdbg("generated sess profile:");
    utils::logdbg("guid: %s", profile.machine_guid.c_str( ));
    utils::logdbg("mac : %s", profile.mac_address.c_str( ));
    utils::logdbg("disk: %s", profile.disk_serial.c_str( ));
    hooks::set_session_profile(profile);

    if (!hooks::init())
    {
        MessageBoxA(nullptr, "cant proceed hooks init :(", xorstr_("github.com/wizenx"), MB_OK | MB_ICONINFORMATION);
        return 1;
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE module_handle, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module_handle);

        HANDLE thread = CreateThread(nullptr, 0, MainThread, module_handle, 0, nullptr);
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
