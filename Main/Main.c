#include <Windows.h>
#include <stdio.h>

int main(void)
{
	HMODULE lama = LoadLibraryA("Tool.dll");

	if (NULL == lama)
	{
		return 0;
	}

	printf("Sleeping\n");

	Sleep(INFINITE);

	FreeLibrary(lama);

	return 0;
}