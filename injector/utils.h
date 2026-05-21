#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <filesystem>
#include <fstream>

namespace utils {
    bool is_process_running(const std::string& processName) {
        bool exists = false;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe)) {
                do {
                    if (processName == pe.szExeFile) {
                        exists = true;
                        break;
                    }
                    pe.dwSize = sizeof(PROCESSENTRY32);
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return exists;
    }

    DWORD get_pid(const std::string& processName) {
        DWORD processId = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe)) {
                do {
                    if (processName == pe.szExeFile) {
                        processId = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return processId;
    }

    void kill_steam() {
        std::cout << "[*] killing steam process...\n";
        std::system("taskkill /F /IM steam.exe >nul 2>&1");
    }

    std::vector<uint8_t> load_file_from_disk(const std::string& path) {
        if (!std::filesystem::exists(path)) return {};
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open( )) return {};

        size_t size = static_cast<size_t>(file.tellg( ));
        std::vector<uint8_t> buffer(size);
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(buffer.data( )), size);
        return buffer;
    }
}