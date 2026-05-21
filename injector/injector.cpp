#include <iostream>
#include <windows.h>

#include "manualmap.h"
#include "utils.h"
#include "spoofer.h"

int main() {
    std::vector<uint8_t> buffer;
    buffer.assign(spoofer, spoofer + sizeof(spoofer));
    if (!buffer.empty() && buffer.size() > 2 && buffer[0] == 'M' && buffer[1] == 'Z') {

        utils::kill_steam();

        std::cout << "[*] waiting for steam.exe...\n";
        while (!utils::is_process_running("steam.exe")) {
            Sleep(500); 
        }
        DWORD targetPid = utils::get_pid("steam.exe");
        std::cout << "[+] steam found! starting inject...\n";

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProc || hProc == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] failed to open steam proc with all access. open this process as admin\n";
            std::system("pause");
            return 1;
        }

        std::cout << "[*] starting inject...\n";
        
        bool result = ManualMapDll(hProc, buffer.data( ), buffer.size( ), true, true, true, true);

        if (result) {
            std::cout << "[+] success!\n";
        }
        else {
            std::cerr << "[!] failed!\n";
        }

        CloseHandle(hProc);
    }
    else {
        std::cerr << "[!] error: dll have invalid data or empty\n";
        std::system("pause");
        return 1;
    }
    
    std::system("pause");
    return 0;
}