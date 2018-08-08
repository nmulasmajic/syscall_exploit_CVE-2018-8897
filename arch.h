/*
*	Module Name:
*		arch.h
*
*	Abstract:
*		Header file that defines x86-specific architectural types and 
*		structures.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

// The X86 architecture supports only 4 debug registers: DR0, DR1, DR2, and 
// DR3.
enum class DEBUG_REGISTERS
{
	DR0 = 0,
	DR1 = 1,
	DR2 = 2,
	DR3 = 3
};

// A hardware breakpoint can be from 1 to 4 (8 on X64) bytes in size.
enum class BREAKPOINT_SIZE
{
	One = 0,
	Two = 1,
	Eight = 2,
	Four = 3
};

// A hardware breakpoint can occur on data WRITE, ACCESS (READ/WRITE), or 
// EXECUTE.
enum class BREAKPOINT_TYPE
{
	Write = 1,
	Access = 3,
	Execute = 0
};

// The size of a page on the x86 architecture.
#define PAGE_SIZE 0x1000

// The PAGE_ALIGN macro takes a virtual address and returns a page-aligned
// virtual address for that page.
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

// The ROUND_TO_PAGES macro takes a size in bytes and rounds it up to a
// multiple of the page size.
#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

// Atomic bit set.
#define ATOMIC_BOOL_SET(Variable) _interlockedbittestandset((PLONG)&Variable, 0)

// Atomic bit reset.
#define ATOMIC_BOOL_RESET(Variable) _interlockedbittestandreset((PLONG)&Variable, 0)

// With the SMEP-bit disabled.
#define NEW_CR4_VALUE 0x506F8