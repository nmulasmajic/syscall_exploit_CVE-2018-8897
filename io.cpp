/*
*	Module Name:
*		io.cpp
*
*	Abstract:
*		Generic file I/O routines.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#include "stdafx.h"
#include "io.h"
#include "mm.h"

/*
*	Maps a PE file from disk into memory.
*/
bool IoMapImage(_In_ PWCHAR Path,  _Inout_ PVOID& Mapping,  _Inout_ size_t&	Size)
{
	if (!Path)
		return false;

	bool Success = false;

	// Open the file on disk.
	HANDLE FileHandle = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (FileHandle != INVALID_HANDLE_VALUE)
	{
		HANDLE FileMappingHandle = CreateFileMappingW(FileHandle, NULL, (PAGE_READONLY | SEC_IMAGE), 0, 0, NULL);
		if (FileMappingHandle)
		{
			// Map it to memory.
			Mapping = MapViewOfFile(FileMappingHandle, FILE_MAP_READ, 0, 0, 0);
			if (Mapping)
			{
				Size = MmGetRegionSize(Mapping);
				Success = true;
			}

			CloseHandle(FileMappingHandle);
		}

		CloseHandle(FileHandle);
	}

	return Success;
}

/*
*	Retrieves the start address and size of a PE section.
*/
PVOID IoGetImageSection(_In_ PVOID Base, _In_ const char* Name, _Inout_ size_t&	Size)
{
	if (!Name)
		return NULL;

	// Valid 'MZ' header?
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
	if (!DosHeader || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Valid 'PE00' header?
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)DosHeader + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Loop through all the sections.
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		// Does it match the section we're looking for?
		if (!strncmp((const char*)SectionHeader->Name, Name, RTL_NUMBER_OF(SectionHeader->Name)))
		{
			Size = (size_t)SectionHeader->Misc.VirtualSize;
			return (PVOID)((uintptr_t)Base + SectionHeader->VirtualAddress);
		}

		SectionHeader++;
	}

	// Failed to find the section.
	return NULL;
}