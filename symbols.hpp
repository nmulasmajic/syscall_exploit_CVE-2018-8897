/*
*	Module Name:
*		symbols.hpp
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

#pragma once

#include "singleton.hpp"

#define OFFSET_ROP_GADGET_1 ((uintptr_t)_NtoskrnlBaseAddress + _Gadget1Offset)
#define OFFSET_ROP_GADGET_2	((uintptr_t)_NtoskrnlBaseAddress + _Gadget2Offset)
#define OFFSET_ROP_GADGET_3 ((uintptr_t)_NtoskrnlBaseAddress + _Gadget3Offset)

/*
*	A "symbol" module, e.g. ntoskrnl.
*/
class FModule
{
public:
	uint64_t BaseAddress;
	uint32_t ImageSize;
	uint32_t TimeDateStamp;
	uint32_t CheckSum;
	std::wstring ModuleName;
	std::wstring ImageName;
	std::wstring ImagePath;
	std::wstring PdbPath;

	struct FType
	{
		uint32_t ChildId;
		std::wstring MemberName;
		uint32_t TypeId;
		std::wstring TypeName;
		uint32_t Offset;
	};

	inline ~FModule()
	{
		SymUnloadModule64(GetCurrentProcess(), BaseAddress);
	}

	/*
	*	Walk the symbol table, invoking the user-specified callback each time.
	*/
	void EnumerateSymbols(_In_ const wchar_t* Mask, _In_ PSYM_ENUMERATESYMBOLS_CALLBACKW Callback, _In_ void* Context)
	{
#pragma warning(push)
#pragma warning(disable: 5039)
		SymEnumSymbolsW(GetCurrentProcess(), BaseAddress, Mask, Callback, Context);
#pragma warning(pop)
	}

	/*
	*	Given a structure and member, retrieve the offset of the member variable 
	*	within that data structure.
	*/
	std::shared_ptr<FType> GetType(_In_ const wchar_t* Structure, _In_ const wchar_t* Member)
	{
		SYMBOL_INFOW StructureSymbol;
		memset(&StructureSymbol, 0, sizeof(StructureSymbol));

		StructureSymbol.MaxNameLen = 1;
		StructureSymbol.SizeOfStruct = sizeof(StructureSymbol);

		if (!SymGetTypeFromNameW(GetCurrentProcess(), BaseAddress, Structure, &StructureSymbol))
			return NULL;

		DWORD NumberOfChildren;
		if (!SymGetTypeInfo(GetCurrentProcess(), BaseAddress, StructureSymbol.TypeIndex, TI_GET_CHILDRENCOUNT, &NumberOfChildren))
			return NULL;

		std::vector<uint8_t> Buffer;
		Buffer.resize(offsetof(TI_FINDCHILDREN_PARAMS, ChildId) + (sizeof(TI_FINDCHILDREN_PARAMS::ChildId) * NumberOfChildren));

		TI_FINDCHILDREN_PARAMS* Children = (TI_FINDCHILDREN_PARAMS*)Buffer.data();
		Children->Count = NumberOfChildren;
		Children->Start = 0;
		if (!SymGetTypeInfo(GetCurrentProcess(), BaseAddress, StructureSymbol.TypeIndex, TI_FINDCHILDREN, Children))
			return NULL;

		for (DWORD i = 0; i < NumberOfChildren; i++)
		{
			auto& ChildId = Children->ChildId[i];

			wchar_t* SymbolName = NULL;
			if (!SymGetTypeInfo(GetCurrentProcess(), BaseAddress, ChildId, TI_GET_SYMNAME, &SymbolName) || !SymbolName)
				continue;

			if (!_wcsicmp(SymbolName, Member))
			{
				std::shared_ptr<FType> Type = std::make_shared<FType>();

				Type->ChildId = ChildId;
				Type->MemberName.assign(SymbolName);

				if (SymGetTypeInfo(GetCurrentProcess(), BaseAddress, Type->ChildId, TI_GET_TYPEID, &Type->TypeId) && Type->TypeId)
				{
					wchar_t* TypeName = NULL;
					if (SymGetTypeInfo(GetCurrentProcess(), BaseAddress, Type->TypeId, TI_GET_SYMNAME, &TypeName) && TypeName)
					{
						Type->TypeName.assign(TypeName);
						LocalFree(TypeName);
					}
				}

				SymGetTypeInfo(GetCurrentProcess(), BaseAddress, Type->ChildId, TI_GET_OFFSET, &Type->Offset);

				LocalFree(SymbolName);
				return Type;
			}

			LocalFree(SymbolName);
		}

		return NULL;
	}
};

/*
*	The interface.
*/
class FSymbols : TSingleton<FSymbols>
{
private:
	bool _Initialized = false;

public:

	/*
	*	Initialize dbghelp/symsrv with the provided options.
	*/
	inline FSymbols(_In_ uint32_t Options)
	{
		SymSetOptions(Options);
	}

	/*
	*	Cleanup dbghelp/symsrv.
	*/
	inline ~FSymbols()
	{
		if (!ATOMIC_BOOL_RESET(_Initialized))
			return;

		SymCleanup(GetCurrentProcess());
	}

	/*
	*	Initialize the symbol service with the specified symbol path.
	*	This is from where symbols will be retrieved.
	*/
	inline bool Initialize(_In_ const wchar_t* SymbolSearchPath)
	{
		if (ATOMIC_BOOL_SET(_Initialized))
			return false;

		return (SymInitializeW(GetCurrentProcess(), SymbolSearchPath, FALSE) ? true : false);
	}

	/*
	*	Load the appropriate symbols from the symsrv for the specified module.
	*/
	inline std::shared_ptr<FModule> Load(_In_ const wchar_t* ImagePath)
	{
		if (!_Initialized)
			return NULL;

		uint64_t ModuleBaseAddress = SymLoadModuleExW(GetCurrentProcess(), NULL, ImagePath, NULL, 0, 0, NULL, 0);
		if (!ModuleBaseAddress)
			return NULL;

		std::shared_ptr<FModule> Module = std::make_shared<FModule>();
		Module->BaseAddress = ModuleBaseAddress;

		IMAGEHLP_MODULEW64 ModuleInfo;
		memset(&ModuleInfo, 0, sizeof(ModuleInfo));
		ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);
		if (!SymGetModuleInfoW64(GetCurrentProcess(), ModuleBaseAddress, &ModuleInfo))
			return NULL;

		Module->ImageSize = ModuleInfo.ImageSize;
		Module->TimeDateStamp = ModuleInfo.TimeDateStamp;
		Module->CheckSum = ModuleInfo.CheckSum;
		Module->ModuleName.assign(ModuleInfo.ModuleName);
		Module->ImageName.assign(ModuleInfo.ImageName);
		Module->ImagePath.assign(ModuleInfo.LoadedImageName);
		Module->PdbPath.assign(ModuleInfo.LoadedPdbName);

		return Module;
	}
};

bool SymFindKernelOffsets();
bool SympFindRopGadgets(_In_ PWCHAR NtoskrnlPath);