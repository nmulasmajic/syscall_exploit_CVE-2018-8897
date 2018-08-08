/*
*	Module Name:
*		singleton.hpp
*
*	Abstract:
*		Ensures that only one instance of a particular class can be allocated 
*		at a given time.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*		Nemanja (Nemi) Mulasmajic <nm@triplefault.io> | http://triplefault.io/
*
*/

#pragma once

template <typename T>
class TSingleton
{
private:
	static volatile bool _Once;

public:
	inline TSingleton()
	{
		if (ATOMIC_BOOL_SET(_Once))
		{
			__debugbreak();
			return;
		}
	}
};

template <typename T>
volatile bool TSingleton<T>::_Once = false;