/*
*	Module Name:
*		ntint.h
*
*	Abstract:
*		Header file that defines Windows-specific types and structures. An
*		extension of Windows.h.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

#include "arch.h"

#define NtCurrentProcess()			((HANDLE)-1)
#define NtCurrentThread()			((HANDLE)-2)

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _GDI_TEB_BATCH
{
	ULONG_PTR Offset;
	HANDLE HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_INTERNAL
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	LONG ExceptionCode;
	PVOID ActivationContextStackPointer;
#if defined(_M_AMD64)
	UCHAR SpareBytes[24];
#elif defined(_M_IX86)
	UCHAR SpareBytes[36];
#endif
	ULONG TxFsContext;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	wchar_t StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];
	ULONG HardErrorMode;
#if defined(_M_AMD64)
	PVOID Instrumentation[11];
#elif defined(_M_IX86)
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	ULONG IdealProcessorValue;
	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR SoftPatchPtr1;
	PVOID ThreadPoolData;
	PVOID *TlsExpansionSlots;
} TEB_INTERNAL, *PTEB_INTERNAL;

extern "C" IMAGE_DOS_HEADER __ImageBase;

uintptr_t WinSetDataBreakpoint(_In_ uintptr_t Address, _In_ BREAKPOINT_SIZE Size, _In_ DEBUG_REGISTERS	Register = DEBUG_REGISTERS::DR0, _In_ BREAKPOINT_TYPE Type = BREAKPOINT_TYPE::Access);