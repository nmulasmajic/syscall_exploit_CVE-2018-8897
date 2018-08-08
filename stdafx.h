/*
*	Module Name:
*		stdafx.h
*
*	Abstract:
*		Precompiled header.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

#pragma warning(push, 0)
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <intrin.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <Shlwapi.h>

#include <stdint.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <memory>

#include "ntint.h"
#pragma warning(pop)