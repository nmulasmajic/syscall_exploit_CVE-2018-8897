/*
*	Module Name:
*		asm.h
*
*	Abstract:
*		Exposes the routines defined in assembly (asm.asm) to C++
*		code.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

extern "C"
{
	void __cdecl AsmExecuteExploit();
	void __stdcall AsmKernelPayload();
	void __cdecl AsmClobberValue(_Inout_ PVOID* Address, _In_ uintptr_t Value);

	void __cdecl __store_ss(_Inout_ uint16_t* SelectorSs);
	void __cdecl __writegsbase(_In_ PVOID NewBase);
	PVOID __cdecl __readgsbase();
}