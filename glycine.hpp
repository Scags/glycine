#pragma once

#ifndef GLYCINE_XOR
#	define GLYCINE_XOR 0x69
#endif

#include <cstdint>
#include <type_traits>

#include <Windows.h>

namespace glycine
{
	static __forceinline uint32_t CRC32(const void *data, size_t len)
	{		
		uint32_t crc = 0xFFFFFFFF;
		for (size_t i = 0; i < len; i++)
		{
			crc ^= ((const uint8_t *)data)[i];
			for (int k = 0; k < sizeof(void*); k++)
			{
				crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
			}
		}
		return ~crc;
	}

#pragma pack(push, 1)
	struct function_info
	{
		// Address CRC32
		uint32_t addresscrc;
		// Byte size of function
		uint32_t size;
		// Unencrypted CRC32
		uint32_t crc32;

		__forceinline bool encrypted(const void* address, uint32_t len) const volatile
		{
			return crc32 != CRC32(address, len);
		}

		__forceinline bool encrypted(uint32_t crc) const volatile
		{
			return crc32 != crc;
		}
	};
#pragma pack(pop)

	// Memory address is populated in postscript
	volatile function_info* functions = (function_info*)0xcafecafef00df00d;

	volatile static __forceinline function_info* GetFunctionInfo(uint32_t crc)
	{
		// Should have every encrypted function in the module in this array
		// If not, then the post script didn't run or Capstone pooped itself
		// Crashing is a preferable alternative to Communism
		for (uint32_t i = 0;;i++)
		{
			if (functions[i].addresscrc == crc)
				return &functions[i];
		}
		return nullptr;
	}

	__declspec(noinline) static bool Cipher(auto fn)
	{
		// Allow dry runs to assure that everything works as normal
#ifdef GLYCINE_DRYRUN
		return false;
#endif
		// CRCing the function pointer is a bit lame but this removes any xrefs which may or may not thwart reversers
		// Although the giant array appended to one of the sections is a huge giveaway
		uint32_t crc = CRC32(&fn, sizeof(&fn));
		volatile function_info* info = GetFunctionInfo(crc);

		if (info->encrypted(crc))
		{
			DWORD oldprotect;
			VirtualProtect((void*)fn, info->size, PAGE_EXECUTE_READWRITE, &oldprotect);
			// Decrypt
			for (uint32_t i = 0; i < info->size; i++)
			{
				((uint8_t*)fn)[i] ^= GLYCINE_XOR;
			}
			VirtualProtect((void*)fn, info->size, oldprotect, &oldprotect);
			return true;
		}
		return false;
	}

	template <typename R, typename... ARGS>
	static R return_type(R (*)(ARGS...)); // Forward declaration only for decltype

	// Ciphers the function if it is encrypted, invokes it with the given arguments, and then reciphers it again if it was encrypted before.
	// The function must have a ReturnType, a pointer to the function fn, and a variadic list of Args.
	// Returns the ReturnType of the invoked function.
	// Return type deduction is some magic from https://stackoverflow.com/a/74985611/21358172
	template <auto fn, typename... Args>
	__declspec(noinline) decltype(return_type(fn)) Invoke(Args... args)
	{
		using ReturnType = decltype(return_type(fn));

		// Capturing ciphers is so we don't accidentally ret into a ciphered function in recursive calls or similar.
		bool recipher = Cipher(fn);
		if constexpr (!std::is_void_v<ReturnType>)
		{
			ReturnType result = std::invoke(fn, args...);
			if (recipher)
			{
				Cipher(fn);
			}
			return result;
		}
		else
		{
			std::invoke(fn, args...);
			if (recipher)
			{
				Cipher(fn);
			}
		}
	}
}