//
// DelayHlp.cpp
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  Implement the delay load helper routines.
//

// Build instructions
// cl -c -O1 -Z7 -Zl -W3 delayhlp.cpp
//
// For ISOLATION_AWARE_ENABLED calls to LoadLibrary(), you will need to add
// a definition for ISOLATION_AWARE_ENABLED to the command line above, eg:
// cl -c -O1 -Z7 -Zl -W3 -DISOLATION_AWARE_ENABLED=1 delayhlp.cpp
//
//
// Then, you can either link directly with this new object file, or replace the one in
// delayimp.lib with your new one, eg:
// lib /out:delayimp.lib delayhlp.obj
//


#include <windows.h>

#include "DelayImp.h"


#include <assert.h>
#include <malloc.h>
#include <search.h>
#include <string.h>
#include <stdio.h>

// header for multi-load extension
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <filesystem>

#include "MemoryModule.c"

#pragma warning( disable : 4345 )

//
// Local copies of strlen, memcmp, and memcpy to make sure we do not need the CRT
//

static inline size_t
__strlen(const char * sz) {
    const char *szEnd = sz;

    while( *szEnd++ ) {
        ;
        }

    return szEnd - sz - 1;
    }

static inline int
__memcmp(const void * pv1, const void * pv2, size_t cb) {
    if (!cb) {
        return 0;
        }

    while ( --cb && *(char *)pv1 == *(char *)pv2 ) {
        pv1 = (char *)pv1 + 1;
        pv2 = (char *)pv2 + 1;
        }

    return  *((unsigned char *)pv1) - *((unsigned char *)pv2);
    }

static inline void *
__memcpy(void * pvDst, const void * pvSrc, size_t cb) {

    void * pvRet = pvDst;

    //
    // copy from lower addresses to higher addresses
    //
    while (cb--) {
        *(char *)pvDst = *(char *)pvSrc;
        pvDst = (char *)pvDst + 1;
        pvSrc = (char *)pvSrc + 1;
        }

    return pvRet;
    }


// utility function for calculating the index of the current import
// for all the tables (INT, BIAT, UIAT, and IAT).
inline unsigned
IndexFromPImgThunkData(PCImgThunkData pitdCur, PCImgThunkData pitdBase) {
    return (unsigned) (pitdCur - pitdBase);
    }

// C++ template utility function for converting RVAs to pointers
//
#if defined(_M_IA64)
#pragma section(".base", long, read)
extern "C"
__declspec(allocate(".base"))
const IMAGE_DOS_HEADER __ImageBase;
#else
extern "C"
const IMAGE_DOS_HEADER __ImageBase;
#endif

template <class X>
X PFromRva(RVA rva) {
    return X(PBYTE(&__ImageBase) + rva);
    }

// utility function for calculating the count of imports given the base
// of the IAT.  NB: this only works on a valid IAT!
inline unsigned
CountOfImports(PCImgThunkData pitdBase) {
    unsigned        cRet = 0;
    PCImgThunkData  pitd = pitdBase;
    while (pitd->u1.Function) {
        pitd++;
        cRet++;
        }
    return cRet;
    }

// For our own internal use, we convert to the old
// format for convenience.
//
struct InternalImgDelayDescr {
    DWORD           grAttrs;        // attributes
    LPCSTR          szName;         // pointer to dll name
    HMODULE *       phmod;          // address of module handle
    PImgThunkData   pIAT;           // address of the IAT
    PCImgThunkData  pINT;           // address of the INT
    PCImgThunkData  pBoundIAT;      // address of the optional bound IAT
    PCImgThunkData  pUnloadIAT;     // address of optional copy of original IAT
    DWORD           dwTimeStamp;    // 0 if not bound,
                                    // O.W. date/time stamp of DLL bound to (Old BIND)
    };

typedef InternalImgDelayDescr *         PIIDD;
typedef const InternalImgDelayDescr *   PCIIDD;

static inline
PIMAGE_NT_HEADERS WINAPI
PinhFromImageBase(HMODULE hmod) {
    return PIMAGE_NT_HEADERS(PBYTE(hmod) + PIMAGE_DOS_HEADER(hmod)->e_lfanew);
    }

static inline
void WINAPI
OverlayIAT(PImgThunkData pitdDst, PCImgThunkData pitdSrc) {
    __memcpy(pitdDst, pitdSrc, CountOfImports(pitdDst) * sizeof IMAGE_THUNK_DATA);
    }

static inline
DWORD WINAPI
TimeStampOfImage(PIMAGE_NT_HEADERS pinh) {
    return pinh->FileHeader.TimeDateStamp;
    }

static inline
bool WINAPI
FLoadedAtPreferredAddress(PIMAGE_NT_HEADERS pinh, HMODULE hmod) {
    return UINT_PTR(hmod) == pinh->OptionalHeader.ImageBase;
    }

static 
PCImgDelayDescr
PiddFromDllName(LPCSTR szDll) {
    PCImgDelayDescr     piddRet = NULL;
    PIMAGE_NT_HEADERS   pinh = PinhFromImageBase(HMODULE(&__ImageBase));

    // Scan the Delay load IAT/INT for the dll in question
    //
    if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size != 0) {
        PCImgDelayDescr pidd = PFromRva<PCImgDelayDescr>(
            pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress
            );

        // Check all of the dlls listed up to the NULL one.
        //
        while (pidd->rvaDLLName != 0) {
            // Check to see if it is the DLL we want
            // Intentionally case sensitive to avoid complication of using the CRT
            // for those that don't use the CRT...the user can replace this with
            // a variant of a case insenstive comparison routine.
            //
            LPCSTR  szDllCur = PFromRva<LPCSTR>(pidd->rvaDLLName);
            size_t  cchDllCur = __strlen(szDllCur);
            if (cchDllCur == __strlen(szDll) &&
//                __memcmp(szDll, szDllCur, cchDllCur) == 0
                   _strnicmp(szDll, szDllCur, cchDllCur) == 0    // use strnicmp for case-insensitive comparison
                ) {
                piddRet = pidd;
                break;
                }
            
            pidd++;
            }
        }
    return piddRet;
    }

// Do the InterlockedExchange magic
//
#ifdef  _M_IX86

#undef  InterlockedExchangePointer
#define InterlockedExchangePointer(Target, Value) \
    (PVOID)(LONG_PTR)InterlockedExchange((PLONG)(Target), (LONG)(LONG_PTR)(Value))

#if (_MSC_VER >= 1300)
typedef __w64 unsigned long *PULONG_PTR;
#else
typedef unsigned long *PULONG_PTR;
#endif

#endif

extern "C"
FARPROC WINAPI
__delayLoadHelper2(
    PCImgDelayDescr     pidd,
    FARPROC *           ppfnIATEntry
    ) {

    // Set up some data we use for the hook procs but also useful for
    // our own use
    //
    InternalImgDelayDescr   idd = {
        pidd->grAttrs,
        PFromRva<LPCSTR>(pidd->rvaDLLName),
        PFromRva<HMODULE*>(pidd->rvaHmod),
        PFromRva<PImgThunkData>(pidd->rvaIAT),
        PFromRva<PCImgThunkData>(pidd->rvaINT),
        PFromRva<PCImgThunkData>(pidd->rvaBoundIAT),
        PFromRva<PCImgThunkData>(pidd->rvaUnloadIAT),
        pidd->dwTimeStamp
        };

    DelayLoadInfo   dli = {
        sizeof DelayLoadInfo,
        pidd,
        ppfnIATEntry,
        idd.szName,
        { 0 },
        0,
        0,
        0
        };

    if (0 == (idd.grAttrs & dlattrRva)) {
        PDelayLoadInfo  rgpdli[1] = { &dli };

        RaiseException(
            VcppException(ERROR_SEVERITY_ERROR, ERROR_INVALID_PARAMETER),
            0,
            1,
            PULONG_PTR(rgpdli)
            );
        return 0;
        }

    HMODULE hmod = *idd.phmod;

    // Calculate the index for the IAT entry in the import address table
    // N.B. The INT entries are ordered the same as the IAT entries so
    // the calculation can be done on the IAT side.
    //
    const unsigned  iIAT = IndexFromPImgThunkData(PCImgThunkData(ppfnIATEntry), idd.pIAT);
    const unsigned  iINT = iIAT;

    PCImgThunkData  pitd = &(idd.pINT[iINT]);

    dli.dlp.fImportByName = !IMAGE_SNAP_BY_ORDINAL(pitd->u1.Ordinal);

    if (dli.dlp.fImportByName) {
        dli.dlp.szProcName = LPCSTR(PFromRva<PIMAGE_IMPORT_BY_NAME>(RVA(UINT_PTR(pitd->u1.AddressOfData)))->Name);
        }
    else {
        dli.dlp.dwOrdinal = DWORD(IMAGE_ORDINAL(pitd->u1.Ordinal));
        }

    // Call the initial hook.  If it exists and returns a function pointer,
    // abort the rest of the processing and just return it for the call.
    //
    FARPROC pfnRet = NULL;

    if (__pfnDliNotifyHook2) {
        pfnRet = ((*__pfnDliNotifyHook2)(dliStartProcessing, &dli));

        if (pfnRet != NULL) {
            goto HookBypass;
            }
        }

    // Check to see if we need to try to load the library.
    //
    if (hmod == 0) {
        if (__pfnDliNotifyHook2) {
            hmod = HMODULE(((*__pfnDliNotifyHook2)(dliNotePreLoadLibrary, &dli)));
            }
        if (hmod == 0) {
            hmod = ::LoadLibraryExA(dli.szDll, NULL, 0);
            }
        if (hmod == 0) {
            dli.dwLastError = ::GetLastError();
            if (__pfnDliFailureHook2) {
                // when the hook is called on LoadLibrary failure, it will
                // return 0 for failure and an hmod for the lib if it fixed
                // the problem.
                //
                hmod = HMODULE((*__pfnDliFailureHook2)(dliFailLoadLib, &dli));
                }

            if (hmod == 0) {
                PDelayLoadInfo  rgpdli[1] = { &dli };

                RaiseException(
                    VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND),
                    0,
                    1,
                    PULONG_PTR(rgpdli)
                    );
                
                // If we get to here, we blindly assume that the handler of the exception
                // has magically fixed everything up and left the function pointer in 
                // dli.pfnCur.
                //
                return dli.pfnCur;
                }
            }

        // Store the library handle.  If it is already there, we infer
        // that another thread got there first, and we need to do a
        // FreeLibrary() to reduce the refcount
        //
        HMODULE hmodT = HMODULE(InterlockedExchangePointer((PVOID *) idd.phmod, PVOID(hmod)));
        if (hmodT == hmod) {
            ::FreeLibrary(hmod);
            }
        }

    // Go for the procedure now.
    //
    dli.hmodCur = hmod;
    if (__pfnDliNotifyHook2) {
        pfnRet = (*__pfnDliNotifyHook2)(dliNotePreGetProcAddress, &dli);
        }
    if (pfnRet == 0) {
        if (pidd->rvaBoundIAT && pidd->dwTimeStamp) {
            // bound imports exist...check the timestamp from the target image
            //
            PIMAGE_NT_HEADERS   pinh(PinhFromImageBase(hmod));

            if (pinh->Signature == IMAGE_NT_SIGNATURE &&
                TimeStampOfImage(pinh) == idd.dwTimeStamp &&
                FLoadedAtPreferredAddress(pinh, hmod)) {

                // Everything is good to go, if we have a decent address
                // in the bound IAT!
                //
                pfnRet = FARPROC(UINT_PTR(idd.pBoundIAT[iIAT].u1.Function));
                if (pfnRet != 0) {
                    goto SetEntryHookBypass;
                    }
                }
            }

        pfnRet = ::GetProcAddress(hmod, dli.dlp.szProcName);
        }

    if (pfnRet == 0) {
        dli.dwLastError = ::GetLastError();
        if (__pfnDliFailureHook2) {
            // when the hook is called on GetProcAddress failure, it will
            // return 0 on failure and a valid proc address on success
            //
            pfnRet = (*__pfnDliFailureHook2)(dliFailGetProc, &dli);
            }
        if (pfnRet == 0) {
            PDelayLoadInfo  rgpdli[1] = { &dli };

            RaiseException(
                VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC_NOT_FOUND),
                0,
                1,
                PULONG_PTR(rgpdli)
                );

            // If we get to here, we blindly assume that the handler of the exception
            // has magically fixed everything up and left the function pointer in 
            // dli.pfnCur.
            //
            pfnRet = dli.pfnCur;
            }
        }

SetEntryHookBypass:
    *ppfnIATEntry = pfnRet;

HookBypass:
    if (__pfnDliNotifyHook2) {
        dli.dwLastError = 0;
        dli.hmodCur = hmod;
        dli.pfnCur = pfnRet;
        (*__pfnDliNotifyHook2)(dliNoteEndProcessing, &dli);
        }
    return pfnRet;
    }

extern "C"
BOOL WINAPI
__FUnloadDelayLoadedDLL2(LPCSTR szDll) {
    BOOL        fRet = FALSE;
    PCImgDelayDescr pidd = PiddFromDllName(szDll);

    if ((pidd != NULL) && 
        (pidd->rvaUnloadIAT != 0)) {
        HMODULE *           phmod = PFromRva<HMODULE*>(pidd->rvaHmod);
        HMODULE             hmod = *phmod;
        if (hmod != NULL) {
            OverlayIAT(
                PFromRva<PImgThunkData>(pidd->rvaIAT),
                PFromRva<PCImgThunkData>(pidd->rvaUnloadIAT)
                );
            ::FreeLibrary(hmod);
            *phmod = NULL;
            fRet = TRUE;
            }

        }
    return fRet;
    }

extern "C"
HRESULT WINAPI
__HrLoadAllImportsForDll(LPCSTR szDll) {
    HRESULT             hrRet = HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
    PCImgDelayDescr     pidd = PiddFromDllName(szDll);

    if (pidd != NULL) {
        // Found a matching DLL name, now process it.
        //
        // Set up the internal structure
        //
        FARPROC *   ppfnIATEntry = PFromRva<FARPROC*>(pidd->rvaIAT);
        size_t      cpfnIATEntries = CountOfImports(PCImgThunkData(ppfnIATEntry));
        FARPROC *   ppfnIATEntryMax = ppfnIATEntry + cpfnIATEntries;

        for (;ppfnIATEntry < ppfnIATEntryMax; ppfnIATEntry++) {
            __delayLoadHelper2(pidd, ppfnIATEntry);
            }

        // Done, indicate some semblance of success
        //
        hrRet = S_OK;
        }
    return hrRet;
    }


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// end of original impementation
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////
//
// multi-load-implementation extension
//
//////////////////////////////////////////////////////////////////////////




/////////////////////////////////
// global data (NOT thread-local)
struct module_descriptor_t {
    module_descriptor_t() = default;
    ~module_descriptor_t(){
        if (data.first) {
            free(data.first);
        }
    }
    std::wstring name;
    int index{};
    std::pair<unsigned char*, size_t> data{};
};

struct function_descriptor_t {
    module_descriptor_t* module_descriptor{};
    bool is_name{};
    std::string name;
    int id{};
};


/////////////////////////////////
// thread-local data

static DWORD stc_tls_dll_index = TlsAlloc();
static DWORD stc_tls_management_index = TlsAlloc();

struct tl_dlls_t {
    // use native C arrays for easy assembler access
    FARPROC* functions; 
    HANDLE* modules;
};

struct tl_management_t {
    tl_management_t() : dlls(1)
    {}

    std::vector<tl_dlls_t*>    dlls;
    size_t active_dll{};
};

tl_management_t* get_management()
{
    tl_management_t* management = (tl_management_t*)TlsGetValue(stc_tls_management_index);
    if(management == nullptr)
    {
        // alloc tls-memory
        LPVOID lpvData = (LPVOID)LocalAlloc(LPTR, sizeof(tl_management_t));
        if(!TlsSetValue(stc_tls_management_index, lpvData))
        {
            terminate();
        }

        // placement new
        management = new(lpvData) tl_management_t();
    }
    return management;
}
////////////////////////////////////////////////////

static DWORD stc_main_thread_id = 0;
// module descriptors for all modules
static std::vector<std::unique_ptr<module_descriptor_t>>    module_descriptors;
static std::vector<std::unique_ptr<function_descriptor_t>>  function_descriptors;


void free_tl_dlls(tl_dlls_t* tl_dlls)
{
    delete[] tl_dlls->functions;

    for(size_t i = 0; i < module_descriptors.size(); ++i)
    {
        MemoryFreeLibrary(tl_dlls->modules[i]);
    }

    delete[] tl_dlls->modules;

    tl_dlls->~tl_dlls_t();
    ::LocalFree(tl_dlls);
}

void free_management(tl_management_t* management)
{
    for(auto&& dll : management->dlls)
    {
        if(dll)
        {
            free_tl_dlls(dll);
        }
    }

    management->~tl_management_t();
    ::LocalFree(management);
}




////////////////////////////////////////////////////


#pragma pack(push, 1)

#ifdef _M_IX86
	struct code_thunk{
        BYTE    m_pre_ld_fs[6];
        BYTE    m_pre_ld_tls[16];
        BYTE    m_pre_ld_func[16];
        BYTE    m_push;     // 68: push imm 32
        DWORD   m_data;
		BYTE	m_mov;			    // B8: mov eax
		DWORD	m_procaddr; 		    //
		WORD	m_calleax;			// FF D0
		BYTE	m_jmp;			// jmp 
		BYTE	m_eax;			// %eax
	};
	struct code_thunk_large_tls_index{
        BYTE    m_pre_ld_fs[6];
        BYTE    m_pre_ld_tls[22];
        BYTE    m_pre_ld_func[16];
        BYTE    m_push;     // 68: push imm 32
        DWORD   m_data;
		BYTE	m_mov;			    // B8: mov eax
		DWORD	m_procaddr; 		    //
		WORD	m_calleax;			// FF D0
		BYTE	m_jmp;			// jmp 
		BYTE	m_eax;			// %eax
	};
#elif defined(_M_X64)
	struct code_thunk{

        BYTE    m_pre_ld_tls[38];

        BYTE    m_post_ld_tls[5];
        BYTE    m_pre_ld_func[20];

        BYTE    m_move_regs_to_shadow[20];
        BYTE    m_sub_rsp[4];
        BYTE    m_move_xmm_to_stack[20];
        BYTE    m_mov_rcx;
        DWORD   m_mov_rcx_data;
        BYTE	m_mov_absproc_to_rax[2];			
		DWORD_PTR	m_absproc;  // absolute address of orig func
        BYTE	m_call_rax[2];		
        BYTE    m_move_stack_to_xmm[20];
        BYTE    m_add_rsp[4];
        BYTE    m_move_shadow_to_regs[20];
        BYTE	m_jmp_rax[2];			
	};

    struct code_thunk_large_tls_index{

        BYTE    m_pre_ld_tls_1[13];
        BYTE    m_pre_ld_tls_2[10];
        BYTE    m_pre_ld_tls_3[23];


        BYTE    m_post_ld_tls[5];
        BYTE    m_pre_ld_func[20];

        BYTE    m_move_regs_to_shadow[20];
        BYTE    m_sub_rsp[4];
        BYTE    m_move_xmm_to_stack[20];
        BYTE    m_mov_rcx;
        DWORD   m_mov_rcx_data;
        BYTE	m_mov_absproc_to_rax[2];			
		DWORD_PTR	m_absproc;  // absolute address of orig func
        BYTE	m_call_rax[2];		
        BYTE    m_move_stack_to_xmm[20];
        BYTE    m_add_rsp[4];
        BYTE    m_move_shadow_to_regs[20];
        BYTE	m_jmp_rax[2];			
	};
#else
#error platform not supported
#endif



#pragma pack(pop) // _ThunkImpl



extern "C"
{
    FARPROC __stdcall get_call(int global_index)
    {
        tl_dlls_t* tl_dlls = (tl_dlls_t*)TlsGetValue(stc_tls_dll_index);
        if(tl_dlls==nullptr)
        {
            // alloc tls-memory
            LPVOID lpvData = (LPVOID) LocalAlloc(LPTR, sizeof(tl_dlls_t)); 
            if (! TlsSetValue(stc_tls_dll_index, lpvData)) 
            {
                terminate();
            }

            // placement new
            tl_dlls = new(lpvData) tl_dlls_t();

            {
                tl_management_t* management = get_management();
                management->dlls[management->active_dll] = tl_dlls;
            }

            tl_dlls->functions = new FARPROC[function_descriptors.size()]();
            tl_dlls->modules = new HANDLE[module_descriptors.size()]();
        }

        auto& function = tl_dlls->functions[global_index];
        if(!function)
        {
            // load function for thread

            // check if module is loaded
            const auto& function_descriptor = function_descriptors[global_index];
            const auto& module_descriptor = function_descriptor->module_descriptor;
            auto& module = tl_dlls->modules[module_descriptor->index];

            if(!module)
            {
                // load module for thread
	            //FILE *fp;

             //   wchar_t szModule[_MAX_PATH] = {};
	            //::GetModuleFileName((HINSTANCE)&__ImageBase, szModule, _MAX_PATH);

             //   std::filesystem::path source_path(szModule);
             //   source_path.remove_filename();
             //   source_path /= module_descriptor->name;

//                tl_management_t* management = get_management();
//                auto&& data = management->data[source_path.wstring()];
//                if(!data.first)
//                {
//                    while(!(fp = _wfopen(source_path.c_str(), L"rb")))
//                    {
//                        switch (errno) {
//                        case ENFILE:
//                        case EMFILE:
//                            // retry
//                            break;
//
//                        default:
//#ifdef _DEBUG
//                            // provoke access error while showing the errno
//                            return (FARPROC)(INT_PTR)errno;
//#else
//                            terminate();
//                            return (FARPROC)0;
//#endif
//                        }
//                        
//                    }
//
//                    fseek(fp, 0, SEEK_END);
//                    data.second = ftell(fp);
//                    data.first = (unsigned char *)malloc(data.second);
//                    fseek(fp, 0, SEEK_SET);
//                    fread(data.first, 1, data.second, fp);
//                    fclose(fp);
//                }

	            module = MemoryLoadLibrary(module_descriptor->data.first, module_descriptor->data.second);
                //free(data.first);

            }

            function = MemoryGetProcAddress(
                (HMEMORYMODULE)module, 
                function_descriptor->is_name ? function_descriptor->name.c_str() : reinterpret_cast<LPCSTR>(static_cast<INT_PTR>(function_descriptor->id))
            );

        }

        return function;
    }



}



#ifdef _M_IX86

template<class thunk_t>
inline void write_asm_load_tls(thunk_t& ct);

template<>
inline void write_asm_load_tls<code_thunk>(code_thunk& ct)
{
    // mov ecx, stc_tls_dll_index
	ct.m_pre_ld_tls[0] = 0xB9;
	*((DWORD*)&ct.m_pre_ld_tls[1]) = stc_tls_dll_index;      // 1 - 4


    // 74FD3C31 8B 84 88 10 0E 00 00 mov         eax,dword ptr [eax+ecx*4+0E10h]  
	ct.m_pre_ld_tls[5] = 0x8B;
	ct.m_pre_ld_tls[6] = 0x84;
	ct.m_pre_ld_tls[7] = 0x88;
	ct.m_pre_ld_tls[8] = 0x10;
	ct.m_pre_ld_tls[9] = 0x0E;
	ct.m_pre_ld_tls[10] = 0x00;
	ct.m_pre_ld_tls[11] = 0x00;

    // check if tls already written
    // 85 C0                test        eax,eax  
	ct.m_pre_ld_tls[12] = 0x85;
	ct.m_pre_ld_tls[13] = 0xC0;
    // 74 F0                je          somewhere
	ct.m_pre_ld_tls[14] = 0x74;
	ct.m_pre_ld_tls[15] = static_cast<BYTE>(((BYTE*)&ct.m_push - (BYTE*)&ct.m_pre_ld_tls[16]));
}

template<>
inline void write_asm_load_tls<code_thunk_large_tls_index>(code_thunk_large_tls_index& ct)
{
    // mov ecx, stc_tls_dll_index
	ct.m_pre_ld_tls[0] = 0xB9;
	*((DWORD*)&ct.m_pre_ld_tls[1]) = stc_tls_dll_index - 64;      // 1 - 4

    // load from extended tls-memory
    // 8B 80 94 0F 00 00    mov         eax,dword ptr [eax+0F94h]  
    // 85 C0                test        eax,eax  
    // 74 F0                je          76883C4C  
    // 8B 04 88             mov         eax,dword ptr [eax+ecx*4]  

	ct.m_pre_ld_tls[5] = 0x8B;
	ct.m_pre_ld_tls[6] = 0x80;
	ct.m_pre_ld_tls[7] = 0x94;
	ct.m_pre_ld_tls[8] = 0x0F;
	ct.m_pre_ld_tls[9] = 0x00;
	ct.m_pre_ld_tls[10] = 0x00;

	ct.m_pre_ld_tls[11] = 0x85;
	ct.m_pre_ld_tls[12] = 0xC0;

	ct.m_pre_ld_tls[13] = 0x74;

    ct.m_pre_ld_tls[14] = static_cast<BYTE>(((BYTE*)&ct.m_push - (BYTE*)&ct.m_pre_ld_tls[15]));

	ct.m_pre_ld_tls[15] = 0x8B;
	ct.m_pre_ld_tls[16] = 0x04;
	ct.m_pre_ld_tls[17] = 0x88;

	ct.m_pre_ld_tls[18] = 0x85;
	ct.m_pre_ld_tls[19] = 0xC0;

    ct.m_pre_ld_tls[20] = 0x74;

    ct.m_pre_ld_tls[21] = static_cast<BYTE>(((BYTE*)&ct.m_push - (BYTE*)&ct.m_pre_ld_tls[22]));
}

template<class thunk_t>
inline void write_asm(thunk_t& ct, int global_index)
{
    // 64 A1 18 00 00 00    mov         eax,dword ptr fs:[00000018h]  
	ct.m_pre_ld_fs[0] = 0x64;
	ct.m_pre_ld_fs[1] = 0xA1;
	ct.m_pre_ld_fs[2] = 0x18;
	ct.m_pre_ld_fs[3] = 0x00;
	ct.m_pre_ld_fs[4] = 0x00;
	ct.m_pre_ld_fs[5] = 0x00;

    write_asm_load_tls(ct);

////////// check if func_ptr is already set

    // 8B 08                mov         ecx,dword ptr [eax]  
	ct.m_pre_ld_func[0] = 0x8B;
	ct.m_pre_ld_func[1] = 0x08;
    // mov edx, global_index
	ct.m_pre_ld_func[2] = 0xBA;
	*((DWORD*)&ct.m_pre_ld_func[3]) = global_index;      // 3 - 6

    // 8D 04 91             mov         eax,[ecx+edx*4]  
    ct.m_pre_ld_func[7] = 0x8B;
	ct.m_pre_ld_func[8] = 0x04;
	ct.m_pre_ld_func[9] = 0x91;


    // 85 C0                test        eax,eax  
	ct.m_pre_ld_func[10] = 0x85;
	ct.m_pre_ld_func[11] = 0xC0;
    // 74 F0                je          somewhere
	ct.m_pre_ld_func[12] = 0x74;
	ct.m_pre_ld_func[13] = static_cast<BYTE>(((BYTE*)&ct.m_push - (BYTE*)&ct.m_pre_ld_func[14]));

    // yes, the address is in eax -> jmp eax
	ct.m_pre_ld_func[14] = 0xFF;
	ct.m_pre_ld_func[15] = 0xE0;


    // call get_call(global_index)

	ct.m_push = 0x68;
	ct.m_data = (DWORD)global_index; // index to access function data
	ct.m_mov = 0xB8;
	ct.m_procaddr = (DWORD)get_call;
	ct.m_calleax  = 0xD0FF;

    // the address is in eax -> jmp eax
	ct.m_jmp  = 0xFF;
	ct.m_eax  = 0xE0;

}

#elif defined(_M_X64)

template<class thunk_t>
inline void write_asm_load_tls(thunk_t& ct);

template<>
inline void write_asm_load_tls<code_thunk>(code_thunk& ct)
{
    // use r10 for stc_tls_dll_index (thus we do not destroy a possible argument in rcx!)
    // r10 is volatile (as r11)
    // mov r10, stc_tls_dll_index
	ct.m_pre_ld_tls[0] = 0x41;
	ct.m_pre_ld_tls[1] = 0xBA;
	*((DWORD*)&ct.m_pre_ld_tls[2]) = stc_tls_dll_index;      // 2 - 5

    // 65 83 3C 25 68 00 00 00 00 cmp         dword ptr gs:[68h],0  
    // 65 4B 8B 04 D5 80 14 00 00 mov         rax,qword ptr gs:[r10*8+1480h]  
    // 74 0C                je                +0C
    // 65 C7 04 25 68 00 00 00 00 00 00 00 mov         dword ptr gs:[68h],0  
    static const BYTE pre_ld_tls_hlp[32] = 
    {
        0x65, 0x83, 0x3C, 0x25, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x65, 0x4B, 0x8B, 0x04, 0xD5, 0x80, 0x14, 0x00, 0x00,

        0x74, 0x0C,
        0x65, 0xC7, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    memcpy(&ct.m_pre_ld_tls[6], pre_ld_tls_hlp, _countof(pre_ld_tls_hlp));
}

template<>
inline void write_asm_load_tls<code_thunk_large_tls_index>(code_thunk_large_tls_index& ct)
{
    // 33 C0                xor         eax,eax  
    // 65 48 0B 04 25 80 17 00 00 or          rax,qword ptr gs:[1780h]  
    // 74 08                je          TlsGetValue+3Dh (076CD161Dh)  
    static const BYTE pre_ld_tls_1_hlp[12] = 
    {
        0x33, 0xC0,
        0x65, 0x48, 0x0B, 0x04, 0x25, 0x80, 0x17, 0x00, 0x00,
        0x74
    };
    memcpy(ct.m_pre_ld_tls_1, pre_ld_tls_1_hlp, _countof(pre_ld_tls_1_hlp));
    
    assert(((BYTE*)&ct.m_pre_ld_tls_3[0] - (BYTE*)&ct.m_pre_ld_tls_1[13]) < 128);
	ct.m_pre_ld_tls_1[12] = BYTE(((BYTE*)&ct.m_pre_ld_tls_3[0] - (BYTE*)&ct.m_pre_ld_tls_1[13]));




    // use r10 for stc_tls_dll_index (thus we do not destroy a possible argument in rcx!)
    // r10 is volatile (as r11)
    // mov r10, (stc_tls_dll_index-64)
	ct.m_pre_ld_tls_2[0] = 0x41;
	ct.m_pre_ld_tls_2[1] = 0xBA;
	*((DWORD*)&ct.m_pre_ld_tls_2[2]) = stc_tls_dll_index - 64;      // 2 - 5



    // 4a 8B 04 D0       mov         rax,qword ptr [rax+r10*8]  
    static const BYTE pre_ld_tls_2_hlp[4] = 
    {
        0x4A, 0x8B, 0x04, 0xD0
    };
    memcpy(&ct.m_pre_ld_tls_2[6], pre_ld_tls_2_hlp, _countof(pre_ld_tls_2_hlp));
    
    
    // 65 83 3C 25 68 00 00 00 00 cmp         dword ptr gs:[68h],0  
    // 75 01                je               + 0C
    // 65 C7 04 25 68 00 00 00 00 00 00 00 mov         dword ptr gs:[68h],0  

    static const BYTE pre_ld_tls_3_hlp[23] = 
    {
        0x65, 0x83, 0x3C, 0x25, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x74, 0x0C,
        0x65, 0xC7, 0x04, 0x25, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    memcpy(ct.m_pre_ld_tls_3, pre_ld_tls_3_hlp, _countof(pre_ld_tls_3_hlp));
}

template<class thunk_t>
inline void write_asm(thunk_t& ct, int global_index)
{
    write_asm_load_tls(ct);

    // 48 85 C0             test        rax,rax  
    // 74 1F                je          

    static const BYTE post_ld_tls_hlp[4] = 
    {
        0x48, 0x85, 0xC0,
        0x74
    };

    memcpy(ct.m_post_ld_tls, post_ld_tls_hlp, _countof(post_ld_tls_hlp));

    assert(((BYTE*)&ct.m_move_regs_to_shadow[0] - (BYTE*)&ct.m_post_ld_tls[5]) < 128);
	ct.m_post_ld_tls[4] = BYTE(((BYTE*)&ct.m_move_regs_to_shadow[0] - (BYTE*)&ct.m_post_ld_tls[5]));





////////// check if func_ptr is already set

    // 4C 8B 18                mov         r11,dword ptr [eax]  
	ct.m_pre_ld_func[0] = 0x4C;
	ct.m_pre_ld_func[1] = 0x8B;
	ct.m_pre_ld_func[2] = 0x18;

    // mov r10, global_index
	ct.m_pre_ld_func[3] = 0x41;
	ct.m_pre_ld_func[4] = 0xBA;
	*((DWORD*)&ct.m_pre_ld_func[5]) = global_index;      // 5 - 8

    // 4B 8B 04 D3             mov         rax,qword ptr [r11+r10*8]  
    ct.m_pre_ld_func[9] = 0x4B;
    ct.m_pre_ld_func[10] = 0x8B;
	ct.m_pre_ld_func[11] = 0x04;
	ct.m_pre_ld_func[12] = 0xD3;

    // 48 85 C0             test        rax,rax  
	ct.m_pre_ld_func[13] = 0x48;
	ct.m_pre_ld_func[14] = 0x85;
	ct.m_pre_ld_func[15] = 0xC0;

    // 74 1F                je          
	ct.m_pre_ld_func[16] = 0x74;

    assert(((BYTE*)&ct.m_move_regs_to_shadow[0] - (BYTE*)&ct.m_pre_ld_func[18]) < 128);
	ct.m_pre_ld_func[17] = BYTE(((BYTE*)&ct.m_move_regs_to_shadow[0] - (BYTE*)&ct.m_pre_ld_func[18]));

//
//    // yes, the address is in eax -> jmp eax
	ct.m_pre_ld_func[18] = 0xFF;
	ct.m_pre_ld_func[19] = 0xE0;


    // call get_call(global_index)

// safe int-registers in shadow space
// 4C 89 4C 24 20       mov         qword ptr [rsp+20h],r9  
// 4C 89 44 24 18       mov         qword ptr [rsp+18h],r8  
// 48 89 54 24 10       mov         qword ptr [rsp+10h],rdx  
// 48 89 4C 24 08       mov         qword ptr [rsp+8],rcx  

    static const BYTE move_regs_to_shadow[20] = 
    {
        0x4C, 0x89, 0x4C, 0x24, 0x20,
        0x4C, 0x89, 0x44, 0x24, 0x18,
        0x48, 0x89, 0x54, 0x24, 0x10,
        0x48, 0x89, 0x4C, 0x24, 0x08,
    };

    memcpy(ct.m_move_regs_to_shadow, move_regs_to_shadow, _countof(move_regs_to_shadow));

    // sub rsp, 68h        ; shadow space for callee 4 arguments + 4 xmm regs + 16byte aligned stack
    //  48 83 EC 08          sub         rsp,68h  
    ct.m_sub_rsp[0] = 0x48;
    ct.m_sub_rsp[1] = 0x83;
    ct.m_sub_rsp[2] = 0xEC;
    ct.m_sub_rsp[3] = 0x68;


    // save xmm0-3
    //movaps [rsp+20h], xmm0 
    //movaps [rsp+30h], xmm1 
    //movaps [rsp+40h], xmm2 
    //movaps [rsp+50h], xmm3 
    static const BYTE move_xmm_to_stack[20] = 
    {
        0x0F, 0x29, 0x44, 0x24, 0x20,
        0x0F, 0x29, 0x4C, 0x24, 0x30,
        0x0F, 0x29, 0x54, 0x24, 0x40,
        0x0F, 0x29, 0x5C, 0x24, 0x50,
    };

    memcpy(ct.m_move_xmm_to_stack, move_xmm_to_stack, _countof(move_xmm_to_stack));


//            0xB9                      // mov         rcx, imm32

    ct.m_mov_rcx = 0xB9;
    ct.m_mov_rcx_data = (DWORD)global_index; // index to access function data

    ct.m_mov_absproc_to_rax[0]  = 0x48;
	ct.m_mov_absproc_to_rax[1]  = 0xB8;
	ct.m_absproc = (DWORD_PTR)&get_call;

    ct.m_call_rax[0]  = 0xFF;
	ct.m_call_rax[1]  = 0xD0;

    // reinstall xmm0-3
    //movaps xmm0, [rsp+20h]  
    //movaps xmm1, [rsp+30h]  
    //movaps xmm2, [rsp+40h]  
    //movaps xmm3, [rsp+50h]  
    static const BYTE move_stack_to_xmm[20] = 
    {
        0x0F, 0x28, 0x44, 0x24, 0x20,
        0x0F, 0x28, 0x4C, 0x24, 0x30,
        0x0F, 0x28, 0x54, 0x24, 0x40,
        0x0F, 0x28, 0x5C, 0x24, 0x50,
    };

    memcpy(ct.m_move_stack_to_xmm, move_stack_to_xmm, _countof(move_stack_to_xmm));



    // add rsp, 68h        ; shadow space for callee 4 arguments + 4 xmm regs + 16byte aligned stack
    //  48 83 EC 08          add         rsp,68h  
    ct.m_add_rsp[0] = 0x48;
    ct.m_add_rsp[1] = 0x83;
    ct.m_add_rsp[2] = 0xC4;  
    ct.m_add_rsp[3] = 0x68;


// 4C 8B 4C 24 20       mov         r9  ,qword ptr [rsp+20h]
// 4C 8B 44 24 18       mov         r8  ,qword ptr [rsp+18h]
// 48 8B 54 24 10       mov         rdx ,qword ptr [rsp+10h] 
// 48 8B 4C 24 08       mov         rcx ,qword ptr [rsp+8]   

    static const BYTE move_shadow_to_regs[20] = 
    {
        0x4C, 0x8B, 0x4C, 0x24, 0x20,
        0x4C, 0x8B, 0x44, 0x24, 0x18,
        0x48, 0x8B, 0x54, 0x24, 0x10,
        0x48, 0x8B, 0x4C, 0x24, 0x08,
    };

    memcpy(ct.m_move_shadow_to_regs, move_shadow_to_regs, _countof(move_shadow_to_regs));


    ct.m_jmp_rax[0]  = 0xFF;
	ct.m_jmp_rax[1]  = 0xE0;
    
}


#else
#error platform not supported
#endif


FARPROC WINAPI multi_load_DliGetProcAddress(PDelayLoadInfo pdli, int global_index, LPVOID code_thunk_memory)
{
    if(stc_tls_dll_index < 64)
    {
        typedef code_thunk ct_type;
		ct_type* p_code_thunk = reinterpret_cast<ct_type*>(code_thunk_memory);
        write_asm(*p_code_thunk, global_index);
        return (FARPROC)p_code_thunk;
    }
    else if(stc_tls_dll_index < 1088 /*64 + 1024*/)
    {
        typedef code_thunk_large_tls_index ct_type;
		ct_type* p_code_thunk = reinterpret_cast<ct_type*>(code_thunk_memory);
        write_asm(*p_code_thunk, global_index);
        return (FARPROC)p_code_thunk;
    }
    else
    {
        // invalid tls-index
        terminate();
        return nullptr;
    }

    return nullptr;
}



extern "C"
    FARPROC WINAPI
    __delayLoadHelper2_multi_load(
    PCImgDelayDescr     pidd,
    FARPROC *           ppfnIATEntry,
    function_descriptor_t* function_descriptor,
    int global_index,
    LPVOID code_thunk_memory
    ) {

        // Set up some data we use for the hook procs but also useful for
        // our own use
        //
        InternalImgDelayDescr   idd = {
            pidd->grAttrs,
            PFromRva<LPCSTR>(pidd->rvaDLLName),
            PFromRva<HMODULE*>(pidd->rvaHmod),
            PFromRva<PImgThunkData>(pidd->rvaIAT),
            PFromRva<PCImgThunkData>(pidd->rvaINT),
            PFromRva<PCImgThunkData>(pidd->rvaBoundIAT),
            PFromRva<PCImgThunkData>(pidd->rvaUnloadIAT),
            pidd->dwTimeStamp
        };

        DelayLoadInfo   dli = {
            sizeof DelayLoadInfo,
            pidd,
            ppfnIATEntry,
            idd.szName,
            { 0 },
            0,
            0,
            0
        };

        if (0 == (idd.grAttrs & dlattrRva)) {
            PDelayLoadInfo  rgpdli[1] = { &dli };

            RaiseException(
                VcppException(ERROR_SEVERITY_ERROR, ERROR_INVALID_PARAMETER),
                0,
                1,
                PULONG_PTR(rgpdli)
                );
            return 0;
        }

        HMODULE hmod = *idd.phmod;

        // Calculate the index for the IAT entry in the import address table
        // N.B. The INT entries are ordered the same as the IAT entries so
        // the calculation can be done on the IAT side.
        //
        const unsigned  iIAT = IndexFromPImgThunkData(PCImgThunkData(ppfnIATEntry), idd.pIAT);
        const unsigned  iINT = iIAT;

        PCImgThunkData  pitd = &(idd.pINT[iINT]);

        dli.dlp.fImportByName = !IMAGE_SNAP_BY_ORDINAL(pitd->u1.Ordinal);
        function_descriptor->is_name = dli.dlp.fImportByName != FALSE;

        if (dli.dlp.fImportByName) {
            dli.dlp.szProcName = LPCSTR(PFromRva<PIMAGE_IMPORT_BY_NAME>(RVA(UINT_PTR(pitd->u1.AddressOfData)))->Name);
            function_descriptor->name = dli.dlp.szProcName;
            function_descriptor->id = -1;
        }
        else {
            dli.dlp.dwOrdinal = DWORD(IMAGE_ORDINAL(pitd->u1.Ordinal));
            function_descriptor->id = dli.dlp.dwOrdinal;
        }




        // Call the initial hook.  If it exists and returns a function pointer,
        // abort the rest of the processing and just return it for the call.
        //
        FARPROC pfnRet = NULL;

        // Go for the procedure now.
        //
        dli.hmodCur = hmod;
        pfnRet = multi_load_DliGetProcAddress(&dli, global_index, code_thunk_memory);

        if (pfnRet == 0) {
            dli.dwLastError = ::GetLastError();
            if (pfnRet == 0) {
                PDelayLoadInfo  rgpdli[1] = { &dli };

                RaiseException(
                    VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC_NOT_FOUND),
                    0,
                    1,
                    PULONG_PTR(rgpdli)
                    );

                // If we get to here, we blindly assume that the handler of the exception
                // has magically fixed everything up and left the function pointer in 
                // dli.pfnCur.
                //
                pfnRet = dli.pfnCur;
            }
        }

        *ppfnIATEntry = pfnRet;

        dli.dwLastError = 0;
        dli.hmodCur = hmod;
        dli.pfnCur = pfnRet;

        return pfnRet;
}


// set up a new dll-instance for the current thread
extern "C" size_t NewAutoParallelDll()
{
    tl_management_t* management = get_management();
    if(!management->dlls[management->active_dll])
    {
        management->dlls[management->active_dll] = (tl_dlls_t*)TlsGetValue(stc_tls_dll_index);
    }
    management->active_dll = management->dlls.size();
    management->dlls.emplace_back();
    TlsSetValue(stc_tls_dll_index, nullptr);
    return management->active_dll;
}

// active dll-instance for current thread
extern "C" void ActivateAutoParallelDll(size_t index)
{
    tl_management_t* management = get_management();
    if(index != management->active_dll)
    {
        if(!management->dlls[management->active_dll])
        {
            management->dlls[management->active_dll] = (tl_dlls_t*)TlsGetValue(stc_tls_dll_index);
        }
        TlsSetValue(stc_tls_dll_index, management->dlls[index]);
        management->active_dll = index;
    }
}


extern "C" void ExitThreadAutoParallelDll()
{
    tl_management_t* management = get_management();
    if(management)
    {
        free_management(management);
    }
}


extern "C" HRESULT WINAPI InitAutoParallelDll(LPCSTR szDlls[], size_t count)
{
#ifdef MULTILOAD_TEST_LARGE_TLS_INDICES
    // for testing purposes: force stc_tls_dll_index to be in extended tls-memory (>= 64 and < 1088)
    for(int i = 0 ; i <100; ++i)
    {
        stc_tls_dll_index = TlsAlloc();
    }

    if(stc_tls_dll_index == TLS_OUT_OF_INDEXES)
    {
        terminate();
    }
#endif // MULTILOAD_TEST_LARGE_TLS_INDICES

    stc_main_thread_id = GetCurrentThreadId();
    module_descriptors.reserve(count);


    for(size_t index = 0; index != count; ++index)
    {
        const auto& szDll = szDlls[index];
        auto const& module_descriptor = module_descriptors.emplace_back(std::make_unique<module_descriptor_t>());

        module_descriptor->name = std::wstring(szDll, szDll+strlen(szDll));
        module_descriptor->index = (int)index;

        PCImgDelayDescr     pidd = PiddFromDllName(szDll);

        if (!pidd) {
            return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
        } else {
            // Found a matching DLL name, now process it.
            //

            // load module into memory block
            {
                wchar_t szModule[_MAX_PATH] = {};
                ::GetModuleFileName((HINSTANCE)&__ImageBase, szModule, _MAX_PATH);

                std::filesystem::path source_path(szModule);
                source_path.remove_filename();
                source_path /= module_descriptor->name;

                FILE* fp = _wfopen(source_path.c_str(), L"rb");
                if(!fp)
                {
                    switch (errno) {
                    case ENFILE:
                    case EMFILE:
                        return HRESULT_FROM_WIN32(ERROR_TOO_MANY_OPEN_FILES);

                    default:
                        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
                    }
                }

                fseek(fp, 0, SEEK_END);
                module_descriptor->data.second = ftell(fp);
                module_descriptor->data.first = (unsigned char*)malloc(module_descriptor->data.second);
                fseek(fp, 0, SEEK_SET);
                fread(module_descriptor->data.first, 1, module_descriptor->data.second, fp);
                fclose(fp);
            }

            // Set up the internal structure
            //
            FARPROC *   ppfnIATEntry = PFromRva<FARPROC*>(pidd->rvaIAT);
            size_t      cpfnIATEntries = CountOfImports(PCImgThunkData(ppfnIATEntry));
            FARPROC *   ppfnIATEntryMax = ppfnIATEntry + cpfnIATEntries;

// allocate a single virtual-space for all calls
            size_t code_thunk_size = stc_tls_dll_index < 64 ? sizeof(code_thunk): sizeof(code_thunk_large_tls_index);
            size_t code_thunks_size = code_thunk_size * cpfnIATEntries;
            LPVOID code_thunks_memory = VirtualAlloc (NULL, 
                code_thunks_size,
                MEM_COMMIT, PAGE_READWRITE);

            if (!code_thunks_memory) {
                return HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
            }
            LPVOID code_thunk_memory = code_thunks_memory;
            for (;ppfnIATEntry < ppfnIATEntryMax; ppfnIATEntry++, code_thunk_memory = static_cast<char*>(code_thunk_memory) + code_thunk_size)
            {
                auto const& function_descriptor = function_descriptors.emplace_back(std::make_unique<function_descriptor_t>());
                function_descriptor->module_descriptor = module_descriptor.get();
                auto proc = __delayLoadHelper2_multi_load(
                    pidd, 
                    ppfnIATEntry, 
                    function_descriptor.get(),
                    (int)function_descriptors.size()-1,
                    code_thunk_memory
                    );
            }

	        DWORD dwOldProtect;
	        VirtualProtect( code_thunks_memory, code_thunks_size, PAGE_EXECUTE, &dwOldProtect );

	        ::FlushInstructionCache(GetCurrentProcess(), code_thunks_memory, code_thunks_size);
        }
    }

    return S_OK;

}

