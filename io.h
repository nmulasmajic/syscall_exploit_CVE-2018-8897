/*
*	Module Name:
*		io.h
*
*	Abstract:
*		Generic file I/O routines.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

bool IoMapImage(_In_ PWCHAR Path, _Inout_ PVOID& Mapping, _Inout_ size_t& Size);
PVOID IoGetImageSection(_In_ PVOID Base, _In_ const char* Name, _Inout_ size_t& Size);