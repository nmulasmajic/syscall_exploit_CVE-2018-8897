/*
*	Module Name:
*		mm.h
*
*	Abstract:
*		Generic memory manipulation routines.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

size_t MmGetRegionSize(_In_ PVOID Region);
PVOID MmFindBytes(_In_ const uint8_t* Haystack, _In_ size_t HaystackSize, _In_ const uint8_t* Needle, _In_ size_t NeedleSize);
void MmProbeAndLockPages(_In_ PVOID	StartAddress, _In_ size_t RegionSize);