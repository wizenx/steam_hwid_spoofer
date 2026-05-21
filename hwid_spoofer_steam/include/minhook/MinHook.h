



























#pragma once

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
    #error MinHook supports only x86 and x64 systems.
#endif

#include <windows.h>


typedef enum MH_STATUS
{
    
    MH_UNKNOWN = -1,

    
    MH_OK = 0,

    
    MH_ERROR_ALREADY_INITIALIZED,

    
    MH_ERROR_NOT_INITIALIZED,

    
    MH_ERROR_ALREADY_CREATED,

    
    MH_ERROR_NOT_CREATED,

    
    MH_ERROR_ENABLED,

    
    
    MH_ERROR_DISABLED,

    
    
    MH_ERROR_NOT_EXECUTABLE,

    
    MH_ERROR_UNSUPPORTED_FUNCTION,

    
    MH_ERROR_MEMORY_ALLOC,

    
    MH_ERROR_MEMORY_PROTECT,

    
    MH_ERROR_MODULE_NOT_FOUND,

    
    MH_ERROR_FUNCTION_NOT_FOUND
}
MH_STATUS;



#define MH_ALL_HOOKS NULL

#ifdef __cplusplus
extern "C" {
#endif

    
    
    MH_STATUS WINAPI MH_Initialize(VOID);

    
    
    MH_STATUS WINAPI MH_Uninitialize(VOID);

    
    
    
    
    
    
    
    
    
    MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);

    
    
    
    
    
    
    
    
    
    
    
    MH_STATUS WINAPI MH_CreateHookApi(
        LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal);

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    MH_STATUS WINAPI MH_CreateHookApiEx(
        LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, LPVOID *ppOriginal, LPVOID *ppTarget);

    
    
    
    MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget);

    
    
    
    
    
    MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget);

    
    
    
    
    
    MH_STATUS WINAPI MH_DisableHook(LPVOID pTarget);

    
    
    
    
    
    MH_STATUS WINAPI MH_QueueEnableHook(LPVOID pTarget);

    
    
    
    
    
    MH_STATUS WINAPI MH_QueueDisableHook(LPVOID pTarget);

    
    MH_STATUS WINAPI MH_ApplyQueued(VOID);

    
    const char * WINAPI MH_StatusToString(MH_STATUS status);

#ifdef __cplusplus
}
#endif
