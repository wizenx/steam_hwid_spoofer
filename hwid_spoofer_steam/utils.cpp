#include "utils.h"

#include <Windows.h>

#include <array>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace utils
{
    std::mt19937 make_rng()
    {
        std::random_device random_device;
        return std::mt19937(random_device());
    }

    std::string gen_rand_guid()
    {
        static constexpr char k_hex_chars[] = "0123456789abcdef";

        auto engine = make_rng();
        std::uniform_int_distribution<> distribution(0, 15);

        std::string guid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
        for (char& character : guid)
        {
            if (character == 'x')
            {
                character = k_hex_chars[distribution(engine)];
            }
            else if (character == 'y')
            {
                character = k_hex_chars[(distribution(engine) & 0x3) | 0x8];
            }
        }

        return guid;
    }

    std::string gen_rand_mac() {
        std::random_device rd;
        std::mt19937 engine(rd( ));
        std::uniform_int_distribution<> dist(0, 255);

        std::array<uint8_t, 6> mac;
        for (uint8_t& byte : mac) {
            byte = static_cast<uint8_t>(dist(engine));
        }

        mac[0] = (mac[0] & 0xFC) | 0x02;

        char buffer[18];
        std::snprintf(buffer, sizeof(buffer), "%02X-%02X-%02X-%02X-%02X-%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return std::string(buffer);
    }
    std::string gen_rand_disk()
    {
        static constexpr char k_hex_chars[] = "0123456789ABCDEF";

        auto engine = make_rng();
        std::uniform_int_distribution<> distribution(0, 15);

        std::string serial = "0000_0000_0000_0001_xxxx_xxxx_xxxx_xxxx.";
        for (char& character : serial)
        {
            if (character == 'x')
            {
                character = k_hex_chars[distribution(engine)];
            }
        }

        return serial;
    }

    #ifndef NDEBUG
    void logdbg(const char* format, ...)
    {
        printf("[github.com/wizenx] ");

        va_list args;
        va_start(args, format);
        vprintf(format, args);
        printf("\n");
        va_end(args);
    }

    void initconsole()
    {
        if (!AllocConsole())
        {
            return;
        }

        FILE* stream = nullptr;
        freopen_s(&stream, "CONOUT$", "w", stdout);
    }
    #else
    void logdbg(const char*, ...)
    {
    }

    void initconsole()
    {
    }
    #endif

    uintptr_t find_pattern(const char* module_name, const char* pattern)
    {
        std::vector<int> pattern_bytes;
        const char* current = pattern;
        const char* end = pattern + strlen(pattern);

        while (current < end)
        {
            if (*current == ' ')
            {
                ++current;
                continue;
            }

            if (*current == '?')
            {
                pattern_bytes.push_back(-1);
                ++current;

                if (current < end && *current == '?')
                {
                    ++current;
                }

                continue;
            }

            if (std::isxdigit(static_cast<unsigned char>(*current)))
            {
                pattern_bytes.push_back(static_cast<int>(strtol(current, nullptr, 16)));

                while (current + 1 < end && std::isxdigit(static_cast<unsigned char>(*(current + 1))))
                {
                    ++current;
                }
            }

            ++current;
        }

        HMODULE module_handle = GetModuleHandleA(module_name);
        if (module_handle == nullptr)
        {
            return 0;
        }

        const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_handle);
        const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(module_handle) + dos_header->e_lfanew);

        const uintptr_t image_size = nt_headers->OptionalHeader.SizeOfImage;
        const BYTE* scan_start = reinterpret_cast<const BYTE*>(module_handle);

        if (pattern_bytes.empty() || image_size < pattern_bytes.size())
        {
            return 0;
        }

        const uintptr_t last_start = image_size - pattern_bytes.size();
        for (uintptr_t offset = 0; offset <= last_start; ++offset)
        {
            bool matches = true;

            for (size_t index = 0; index < pattern_bytes.size(); ++index)
            {
                if (pattern_bytes[index] != -1 &&
                    scan_start[offset + index] != static_cast<BYTE>(pattern_bytes[index]))
                {
                    matches = false;
                    break;
                }
            }

            if (matches)
            {
                return reinterpret_cast<uintptr_t>(scan_start + offset);
            }
        }

        return 0;
    }

    uintptr_t get_absolute_address(uintptr_t address)
    {
        if (address == 0)
        {
            return 0;
        }

        const auto relative_offset = *reinterpret_cast<int32_t*>(address + 1);
        return address + 5 + relative_offset;
    }

    session_profile generate_session_profile()
    {
        session_profile profile;
        profile.machine_guid = gen_rand_guid();
        profile.mac_address = gen_rand_mac();
        profile.disk_serial = gen_rand_disk();
        return profile;
    }
} 
