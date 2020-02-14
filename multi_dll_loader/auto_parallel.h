//
// multiload.h
//


#include <windows.h>

// register dlls to be used with multi-load
extern "C" HRESULT WINAPI InitAutoParallelDll(LPCSTR szDlls[], size_t count);

// inform that a thread is about to die (call from DllMain for call_reasons DLL_THREAD_DETACH and DLL_PROCESS_DETACH)
extern "C" void ExitThreadAutoParallelDll();

// set up a new dll-instance for the current thread
// return index of new instance
extern "C" size_t NewAutoParallelDll();

// active dll-instance for current thread
extern "C" void ActivateAutoParallelDll(size_t index);



