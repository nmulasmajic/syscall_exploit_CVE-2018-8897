/*
*	Module Name:
*		mm.cpp
*
*	Abstract:
*		Generic memory manipulation routines.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#include "stdafx.h"
#include "mm.h"

/*
*	Gets the size of the allocation.
*/
size_t MmGetRegionSize(_In_ PVOID Region)
{
	uintptr_t Current = (uintptr_t)PAGE_ALIGN(Region);

	// First, get the region size for this page.
	MEMORY_BASIC_INFORMATION First;
	if (!VirtualQuery((PVOID)Current, &First, sizeof(First)))
		return 0;

	Current = (uintptr_t)First.BaseAddress + First.RegionSize;

	for (MEMORY_BASIC_INFORMATION Mbi;
		/* */;
		Current += Mbi.RegionSize)
	{
		if (!VirtualQuery((PVOID)Current, &Mbi, sizeof(Mbi)))
			break;

		if (Mbi.State == MEM_FREE)
			break;

		if (Mbi.AllocationBase != First.AllocationBase)
			break;
	}

	return (Current - (uintptr_t)Region);
}

/*
*	Searches for the user-supplied byte pattern (needle) in a region of
*	memory (haystack).
*
*	NOTE: This version doesn't support wildcards.
*/
PVOID MmFindBytes(_In_ const uint8_t* Haystack, _In_ size_t HaystackSize, _In_ const uint8_t* Needle, _In_ size_t NeedleSize)
{
	// Walk haystack.
	for (size_t HaystackIndex = 0; (HaystackIndex + NeedleSize) <= HaystackSize; ++HaystackIndex)
	{
		// Search for needle.
		if (memcmp(&Haystack[HaystackIndex], Needle, NeedleSize) == 0)
		{
			return (PVOID)&Haystack[HaystackIndex];
		}
	}

	return NULL;
}

/*
*	A hint to the memory manager to leave the region paged into RAM.
*/
void MmProbeAndLockPages(_In_ PVOID	StartAddress, _In_ size_t RegionSize)
{
	RegionSize = ROUND_TO_PAGES(RegionSize);
	PBYTE Initial = (PBYTE)PAGE_ALIGN(StartAddress);

	// Make sure all the pages are writable.
	DWORD Old = 0;
	VirtualProtect(Initial, RegionSize, PAGE_EXECUTE_READWRITE, &Old);

	for (volatile PBYTE Current = Initial;
		(Current < (Initial + RegionSize));
		Current++)
	{
		// Write to the page, mapping it in.
		*Current = *Current;
	}

	VirtualLock(Initial, RegionSize);
}