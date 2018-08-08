#include "stdafx.h"
#include "ntint.h"

/*
*	Sets a data breakpoint (hardware breakpoint) on a user-supplied address.
*/
uintptr_t WinSetDataBreakpoint(_In_ uintptr_t Address, _In_ BREAKPOINT_SIZE Size, _In_ DEBUG_REGISTERS Register, _In_ BREAKPOINT_TYPE Type)
{
	// 17.2.4: Debug Control Register (DR7)
	static uintptr_t DR7 = 0;

	// L0 through L3 (local breakpoint enable) flags (bits 0, 2, 4, and 6)
	DR7 |= ((uintptr_t)1 << ((uintptr_t)Register << (uintptr_t)1));

	// R/W0 through R/W3 (read/write) fields (bits 16, 17, 20, 21, 24, 25, 28,
	// and 29)
	DR7 |= ((uintptr_t)Type << (((uintptr_t)Register << 2) + 16));

	// LEN0 through LEN3 (Length) fields (bits 18, 19, 22, 23, 26, 27, 30, and
	// 31)
	DR7 |= ((uintptr_t)Size << (((uintptr_t)Register << 2) + 18));

	// The CONTEXT structure needs to be aligned on a 16 byte boundary; this 
	// makes sure that is the case.
	PCONTEXT Context = (PCONTEXT)_aligned_malloc(sizeof(CONTEXT), 16);
	if (!Context)
		return 0;

	memset(Context, 0, sizeof(CONTEXT));

	// Adjust the hardware breakpoints (only).
	Context->ContextFlags = CONTEXT_DEBUG_REGISTERS;

	// Adjust the DR* contents for this thread.
	((uintptr_t*)&Context->Dr0)[(uintptr_t)Register] = Address;
	Context->Dr7 = DR7;

	BOOL bSuccess = SetThreadContext(NtCurrentThread(), Context);

	// Make sure we don't leak any memory.
	_aligned_free(Context);

	return ((bSuccess) ? Address : 0);
}
