# Glycine
A C++ self-encrypting API.

I wrote this a while ago for fun but had no use for it, so I'm releasing it here. I have no idea how well this works as I only used a small/simple test case with it. YMMV.

Glycine is a simple function encryption framework that allows functions to decrypt and encrypt themselves when they are invoked.

# Usage

Using glycine in a program is simple and straightforward:

```cpp
#include "glycine.hpp"
#include <iostream>

int main()
{
	// Invoke<function>(args...)
	glycine::Invoke<printf>("Hello World!\n");
	return 0;
}
```

The only catch is that this requires work to be done after building the program in a post-build script. This is supplied in the `scripts/` folder.

To implement glycine properly into your project, perform the following:
- Assure that you are building in MSVC++ x64.
- Assure that you are using C++20+.
- Assure that you are generating debug information with /DEBUG.
- Turn off ASLR (/DYNAMICBASE:NO).
- Set a fixed base address (/FIXED).
- Set the base address to whatever you like (e.g. /BASE:0x00007FF140000000)
- Set a Post-Build event that executes the glycine post-build script with the first argument being the produced executable and the second argument the PDB file produced by the linker. This will be along the lines of `py C:\dev\glycine\scripts\postbuild.py $(SolutionDir)$(Platform)\$(Configuration)\$(ProjectName).exe $(OutDir)$(TargetName).pdb`

You can probably copy the settings from glycine_test.sln.

`glycine::Invoke` will not work with imported functions, nor will it work with non-literal functions passed as its templated parameter.

# How it Works
Glycine's post-build script mutates the compiled program by encrypting each function that is used in `glycine::Invoke` with a simple XOR, which, on the C++ side, assumes that the function it is about to call is encrypted.

This is done by parsing the PDB produced by the linker, which is essential for this to work.

After invoking the function, Glycine re-encrypts it directly afterwards.

The way that glycine knows if a function is encrypted and its size in bytes is because the post-build script patches in a structure into a readable section of the program that contains the CRC32 of the each `Invoke`d function's address, the function's byte size, and the CRC32 of the unencrypted function bytes. If the current function's bytes are CRC32'd and are not equal to the unencrypted CRC32, then the function is deemed encrypted and Glycine decrypts it before calling it.