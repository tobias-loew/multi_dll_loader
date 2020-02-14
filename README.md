# multi_dll_loader
 demo for automatic per-thread dll-loading; loads an image of a given per-thread (or even multiple per thread with NewAutoParallelDll and ActivateAutoParallelDll)
 
 usable for libraries that use global static memory, but have to run in multi-threaded environments (ATTENTION: dependent dlls are NOT loaded multiple-times)
 
 works ONLY with Windows / Visual Studio
 
 uses delay-load mechanism (code from delayhlp.cpp, part of Visual Studio distribution cf. https://docs.microsoft.com/en-us/cpp/build/reference/linker-support-for-delay-loaded-dlls)
 
 uses MemoryModule library, written by Joachim Bauch, https://github.com/fancycode/MemoryModule

Usage:

- #include "auto_parallel.h" and register dlls for multi-load with InitAutoParallelDll (before the first call into the dll!)
- link dlls for multi-load with /DELAYLOAD
