#pragma once

namespace patterns
{
	inline constexpr char machine_guid_call[] = "E8 ? ? ? ? 0F B6 4D 70";
	inline constexpr char mac_address_call[] = "E8 ? ? ? ? 85 C0 75 37 85 F6";
	inline constexpr char disk_serial_call[] = "E8 ? ? ? ? 84 C0 74 4F 48 8D 8D";
	inline constexpr char localname_call[] = "48 81 EC ? ? ? ? 8B 0D ? ? ? ? 65 48 8B 04 25 ? ? ? ? BA ? ? ? ? 48 8B 04 C8 8B 04 02 39 05 ? ? ? ? 0F 8F ? ? ? ?";
} 
