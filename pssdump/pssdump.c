/*++

Copyright (c) 2013  Microsoft Corporation

Module Name:

    pssdump.c

Abstract:

    Sample program to dump a process snapshot using MiniDumpWriteDump.

Revision History:

    Genghis Karimov (GenghisK)  Jul-2013

--*/

//
// CRT
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//
// Win32
//
#include <windows.h>
#include <dbghelp.h>
#include <ProcessSnapshot.h>


static BOOL CALLBACK
MinidumpCallback (
    __in PVOID Param,
    __in const PMINIDUMP_CALLBACK_INPUT Input,
    __inout PMINIDUMP_CALLBACK_OUTPUT Output
    )

/*++

Routine Description:

    Implements the MiniDumpWriteDump callback (direct call).

Arguments:

    Param - Specifies the value of MINIDUMP_CALLBACK_INFORMATION.Param. Expected
        to be NULL.

    Input - Specifies the callback input message.

    Output - On output, the callback populates this structure with the callback
        response.

Return Value:

    BOOL (context-dependent).

--*/

{
    UNREFERENCED_PARAMETER (Param);


    switch (Input->CallbackType) {
      //
      // Set the output to S_FALSE to tell MiniDumpWriteDump that a snapshot is
      // being dumped.
      //
      case IsProcessSnapshotCallback:
        Output->Status = S_FALSE;
        return TRUE;

      //
      // Speed up by dumping by disabling cancelation callbacks.
      //
      case CancelCallback:
        Output->Cancel = FALSE;
        Output->CheckCancel = FALSE;
        return TRUE;

      //
      // Ignore any read failures during dump generation.
      //
      case ReadMemoryFailureCallback:
        Output->Status = S_OK;
        return TRUE;

      default:
        return TRUE;
    }
}

int __cdecl
wmain (
    __in int argc,
    __in wchar_t* argv[],
    __in wchar_t* envp[]
    )

/*++

Routine Description:

    Program entrypoint.

Arguments:

    argc - Number of arguments.

    argv - Arguments.

    envp - Environment.

Return Value:

    Exit code.

--*/

{
    DWORD rc;
    HRESULT hr;
    DWORD ProcessId;
    HANDLE ProcessHandle;
    HPSS SnapshotHandle;

    HANDLE FileHandle;
    MINIDUMP_TYPE DumpType;
    MINIDUMP_CALLBACK_INFORMATION CallbackInfo;

    static const DWORD CaptureFlags = PSS_CAPTURE_VA_CLONE
                                      | PSS_CAPTURE_VA_SPACE
                                      | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION
                                      | PSS_CAPTURE_HANDLE_TRACE
                                      | PSS_CAPTURE_HANDLES
                                      | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
                                      | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
                                      | PSS_CAPTURE_HANDLE_NAME_INFORMATION
                                      | PSS_CAPTURE_THREADS
                                      | PSS_CAPTURE_THREAD_CONTEXT
                                      | PSS_CREATE_MEASURE_PERFORMANCE;


    UNREFERENCED_PARAMETER (envp);

    //
    // If arguments are specified, open the process specified by the command
    // line.
    //
    if (argc == 2) {
        if ((0 == _wcsicmp (argv[1], L"/h")) || (0 == _wcsicmp (argv[1], L"-h")) ||
            (0 == _wcsicmp (argv[1], L"/?")) || (0 == _wcsicmp (argv[1], L"-?"))) {

            wprintf (L"Usage: pssdump.exe <process ID>\n");
            return 1;
        }

        ProcessId = _wtoi (argv[1]);

        ProcessHandle = OpenProcess (PROCESS_ALL_ACCESS,
                                     FALSE,
                                     ProcessId);
    }
    else {
        ProcessId = GetCurrentProcessId ();
        ProcessHandle = GetCurrentProcess ();
    }

    //
    // Open the output dump file.
    //
    FileHandle = CreateFile (L"snapshot.dmp",
                             GENERIC_WRITE,
                             0,
                             NULL,
                             CREATE_ALWAYS,
                             0,
                             NULL);

    if (FileHandle == INVALID_HANDLE_VALUE) {
        wprintf (L"CreateFile failed: Win32 error %u.\n", GetLastError ());
        return 1;
    }

    //
    // Snapshot the process.
    //
    rc = PssCaptureSnapshot (ProcessHandle,
                             CaptureFlags,
                             CONTEXT_ALL,
                             &SnapshotHandle);

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssCaptureSnapshot failed: Win32 error %u.\n", rc);
        return 1;
    }

    wprintf (L"Snapshot captured.\n");

    //
    // Set up the minidump callback structure.
    //
    ZeroMemory (&CallbackInfo, sizeof (MINIDUMP_CALLBACK_INFORMATION));
    CallbackInfo.CallbackRoutine = MinidumpCallback;
    CallbackInfo.CallbackParam = NULL;

    //
    // Set up the desired dump type.
    //
    DumpType = MiniDumpWithDataSegs
               | MiniDumpWithProcessThreadData
               | MiniDumpWithHandleData
               | MiniDumpWithPrivateReadWriteMemory
               | MiniDumpWithUnloadedModules
               | MiniDumpWithPrivateWriteCopyMemory
               | MiniDumpWithFullMemoryInfo
               | MiniDumpWithThreadInfo
               | MiniDumpWithTokenInformation;

    //
    // Dump the process.
    //
    // N.B. On failure, MiniDumpWriteDump sets the last error to an HRESULT, not
    // a Win32 error code.
    //
    rc = MiniDumpWriteDump ((HANDLE) SnapshotHandle,
                            ProcessId,
                            FileHandle,
                            DumpType,
                            NULL,
                            NULL,
                            &CallbackInfo);

    if (!rc) {
        hr = (HRESULT) GetLastError ();
        wprintf (L"MiniDumpWriteDump failed: HRESULT %08X.\n", hr);
        return 1;
    }

    wprintf (L"Snapshot dumped to snapshot.dmp.\n");

    PssFreeSnapshot (GetCurrentProcess (), SnapshotHandle);

    return 0;
}
