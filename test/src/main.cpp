#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

#include "../../lib/include/NoMercyValidator.h"

int main()
{
	std::cout << "Hello, World!" << std::endl;

	const auto bRet = NMMV_IsValidModule();
	std::cout << "NMMV_IsValidModule: " << bRet << std::endl;

	NMMV_SafeExit();

	std::cout << "Goodbye, World!" << std::endl;

	return EXIT_SUCCESS;
}