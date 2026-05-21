#pragma once

#include "profile.h"

#include <cstdint>

namespace utils
{
	void logdbg(const char* format, ...);
	void initconsole();

	uintptr_t find_pattern(const char* module_name, const char* pattern);
	uintptr_t get_absolute_address(uintptr_t address);
	session_profile generate_session_profile();
} 
