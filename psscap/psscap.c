/*++

Copyright (c) 2013  Microsoft Corporation

Module Name:

    psscap.c

Abstract:

    Sample program using process snapshotting Win32 APIs.

Revision History:

    Genghis Karimov (GenghisK)  Dec-2013  Support for PSS_PROCESS_INFORMATION_2.
    Genghis Karimov (GenghisK)  Jun-2013  Initial revision.

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
#include <ProcessSnapshot.h>


//
// Nomenclature aliases.
//
#define PssQueryProcessInformation PSS_QUERY_PROCESS_INFORMATION
#define PssQueryVaCloneInformation PSS_QUERY_VA_CLONE_INFORMATION
#define PssQueryAuxiliaryPagesInformation PSS_QUERY_AUXILIARY_PAGES_INFORMATION
#define PssQueryVaSpaceInformation PSS_QUERY_VA_SPACE_INFORMATION
#define PssQueryHandleInformation PSS_QUERY_HANDLE_INFORMATION
#define PssQueryThreadInformation PSS_QUERY_THREAD_INFORMATION
#define PssQueryHandleTraceInformation PSS_QUERY_HANDLE_TRACE_INFORMATION
#define PssQueryPerformanceCounters PSS_QUERY_PERFORMANCE_COUNTERS

#define PssWalkAuxiliaryPages PSS_WALK_AUXILIARY_PAGES
#define PssWalkVaSpace PSS_WALK_VA_SPACE
#define PssWalkHandles PSS_WALK_HANDLES
#define PssWalkThreads PSS_WALK_THREADS

//
// Look-up dictionary constructs.
//
typedef struct _KEY_VALUE_PAIR {
    ULONG Value;
    PCWSTR String;
} KEY_VALUE_PAIR, *PKEY_VALUE_PAIR;
typedef struct _KEY_VALUE_PAIR const *PCKEY_VALUE_PAIR;

#define DEFINE_KEY_VALUE_PAIR(v) { (ULONG) v, L#v }

//
// Look-up dictionary for PSS_OBJECT_TYPE Constants.
//
static const KEY_VALUE_PAIR PssObjectTypes[] = {
    DEFINE_KEY_VALUE_PAIR (PSS_OBJECT_TYPE_UNKNOWN),
    DEFINE_KEY_VALUE_PAIR (PSS_OBJECT_TYPE_PROCESS),
    DEFINE_KEY_VALUE_PAIR (PSS_OBJECT_TYPE_THREAD),
    DEFINE_KEY_VALUE_PAIR (PSS_OBJECT_TYPE_MUTANT),
    DEFINE_KEY_VALUE_PAIR (PSS_OBJECT_TYPE_EVENT),
    DEFINE_KEY_VALUE_PAIR (PSS_OBJECT_TYPE_SECTION),
    { 0, NULL }
};

//
// Look-up dictionary for page protection constants.
//
static const KEY_VALUE_PAIR PageProtections[] = {
    DEFINE_KEY_VALUE_PAIR (PAGE_NOACCESS),                      // 0x01
    DEFINE_KEY_VALUE_PAIR (PAGE_READONLY),                      // 0x02
    DEFINE_KEY_VALUE_PAIR (PAGE_READWRITE),                     // 0x04
    DEFINE_KEY_VALUE_PAIR (PAGE_WRITECOPY),                     // 0x08
    DEFINE_KEY_VALUE_PAIR (PAGE_EXECUTE),                       // 0x10
    DEFINE_KEY_VALUE_PAIR (PAGE_EXECUTE_READ),                  // 0x20
    DEFINE_KEY_VALUE_PAIR (PAGE_EXECUTE_READWRITE),             // 0x40
    DEFINE_KEY_VALUE_PAIR (PAGE_EXECUTE_WRITECOPY),             // 0x80
    DEFINE_KEY_VALUE_PAIR (PAGE_GUARD),                         // 0x100
    DEFINE_KEY_VALUE_PAIR (PAGE_NOCACHE),                       // 0x200
    DEFINE_KEY_VALUE_PAIR (PAGE_WRITECOMBINE),                  // 0x400
    { 0, NULL }
};

//
// Look-up dictionary for page state constants.
//
static const KEY_VALUE_PAIR PageStates[] = {
    DEFINE_KEY_VALUE_PAIR (MEM_COMMIT),                         // 0x1000
    DEFINE_KEY_VALUE_PAIR (MEM_RESERVE),                        // 0x2000
    DEFINE_KEY_VALUE_PAIR (MEM_FREE),                           // 0x10000
    { 0, NULL }
};

//
// Look-up dictionary for page type constants.
//
static const KEY_VALUE_PAIR PageTypes[] = {
    DEFINE_KEY_VALUE_PAIR (MEM_PRIVATE),                        // 0x20000
    DEFINE_KEY_VALUE_PAIR (MEM_MAPPED),                         // 0x40000
    DEFINE_KEY_VALUE_PAIR (MEM_IMAGE),                          // 0x1000000
    { 0, NULL }
};

//
// Look-up dictionary for priority values flags.
//
static const KEY_VALUE_PAIR PriorityValueDictionary[] = {
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_LOWEST),
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_BELOW_NORMAL),
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_NORMAL),
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_HIGHEST),
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_ABOVE_NORMAL),
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_TIME_CRITICAL),
    DEFINE_KEY_VALUE_PAIR (THREAD_PRIORITY_IDLE),
    { 0, NULL }
};

//
// Look-up dictionary for priority class values.
//
static const KEY_VALUE_PAIR PriorityClassDictionary[] = {
    DEFINE_KEY_VALUE_PAIR (IDLE_PRIORITY_CLASS),
    DEFINE_KEY_VALUE_PAIR (BELOW_NORMAL_PRIORITY_CLASS),
    DEFINE_KEY_VALUE_PAIR (NORMAL_PRIORITY_CLASS),
    DEFINE_KEY_VALUE_PAIR (ABOVE_NORMAL_PRIORITY_CLASS),
    DEFINE_KEY_VALUE_PAIR (HIGH_PRIORITY_CLASS),
    DEFINE_KEY_VALUE_PAIR (REALTIME_PRIORITY_CLASS ),
    { 0, NULL }
};

//
// Look-up dictionary for various Win32 error codes, specifically including
// those returned by procsnap APIs.
//
static const KEY_VALUE_PAIR Win32ErrorCodes[] = {
    DEFINE_KEY_VALUE_PAIR (ERROR_NOT_FOUND),
    DEFINE_KEY_VALUE_PAIR (ERROR_NO_MORE_ITEMS),
    DEFINE_KEY_VALUE_PAIR (ERROR_PARTIAL_COPY),
    DEFINE_KEY_VALUE_PAIR (ERROR_MORE_DATA),
    DEFINE_KEY_VALUE_PAIR (ERROR_INVALID_HANDLE),
    DEFINE_KEY_VALUE_PAIR (ERROR_NOT_SUPPORTED),
    DEFINE_KEY_VALUE_PAIR (ERROR_BAD_LENGTH),
    DEFINE_KEY_VALUE_PAIR (ERROR_INVALID_PARAMETER),
    DEFINE_KEY_VALUE_PAIR (ERROR_BUFFER_OVERFLOW),
    DEFINE_KEY_VALUE_PAIR (ERROR_ARITHMETIC_OVERFLOW),
    DEFINE_KEY_VALUE_PAIR (ERROR_INVALID_ADDRESS),
    DEFINE_KEY_VALUE_PAIR (ERROR_NOT_ENOUGH_MEMORY),
    DEFINE_KEY_VALUE_PAIR (ERROR_UNIDENTIFIED_ERROR),
    DEFINE_KEY_VALUE_PAIR (ERROR_SUCCESS),
    { 0, NULL }
};
//
// Bitmap print macro for PrintMemoryBasicInformation.
//
#define PRINT_MBI_BITMAP(i, t, b) \
    for ((i) = 0; (t)[(i)].Value; ++(i)) {                                     \
        if ((b) & (t)[(i)].Value) {                                            \
            wprintf (L"                     - %08X %s\n",                      \
                     (t)[(i)].Value, (t)[(i)].String);                         \
        }                                                                      \
    }

//
// Extracts the program counter (aka instruction pointer) from a context record.
//
#ifndef CONTEXT_TO_PROGRAM_COUNTER
#ifdef _X86_
#define CONTEXT_TO_PROGRAM_COUNTER(c) ((c)->Eip)
#endif
#ifdef _AMD64_
#define CONTEXT_TO_PROGRAM_COUNTER(c) ((c)->Rip)
#endif
#ifdef _ARM_
#define CONTEXT_TO_PROGRAM_COUNTER(c) ((c)->Pc)
#endif
#endif


static VOID
PrintUnixEpoch32 (
    __in ULONG Value
    )

/*++

Routine Description:

    Prints (to stdout) the value of a 32-bit UNIX time_t value as text, in the
    following format:

        yyyy-mm-dd HH:mm:ss

    The value is interpreted as GMT time.

Arguments:

    Value - Specifies the timestamp value.

Return Value:

    None.

--*/

{
    int rc;
    struct tm Time;


    rc = _gmtime32_s (&Time, (__time32_t *) &Value);

    if (rc != 0) {
        return;
    }

    wprintf (L"%04u-%02u-%02u %02u:%02u:%02u",
             Time.tm_year + 1900, Time.tm_mon + 1, Time.tm_mday,
             Time.tm_hour, Time.tm_min, Time.tm_sec);

    return;
}

static PCWSTR
LookupDictionary (
    __in ULONG Value,
    __in PCKEY_VALUE_PAIR Dictionary
    )

/*++

Routine Description:

    Looks up a dictionary value.

Arguments:

    Dictionary - Specifies the dictionary to search.

    Value - Specifies the value to search for.

Return Value:

    The string mapping for the value.

--*/

{
    int i;

    for (i = 0; Dictionary[i].String; ++i) {
        if (Dictionary[i].Value == Value) {
            return Dictionary[i].String;
        }
    }

    return NULL;
}

static VOID
PrintBitmap (
    __in ULONG Value,
    __in PCKEY_VALUE_PAIR Dictionary
    )

/*++

Routine Description:

    Prints out a bitmap to stdout.

Arguments:

    Value - Specifies the bitmap value.

    Dictionary - Specifies the look-up dictionary.

Return Value:

    None.

--*/

{
    int i;

    for (i = 0; Dictionary[i].Value; ++i) {
        if ((Value & Dictionary[i].Value) == Dictionary[i].Value) {
            wprintf (L"  %08X %s\n", Dictionary[i].Value, Dictionary[i].String);
        }
    }

    return;
}

static VOID
PrintMemoryBasicInformation (
    __in PMEMORY_BASIC_INFORMATION MemBasicInfo
    )

/*++

Routine Description:

    Prints the contents of a MEMORY_BASIC_INFORMATION to stdout.

Arguments:

    MemBasicInfo - Specifies the structure to print.

Return Value:

    None.

--*/

{
    int i;


    wprintf (L"MEMORY_BASIC_INFORMATION:\n");
    wprintf (L"        BaseAddress: %p\n", MemBasicInfo->BaseAddress);
    wprintf (L"     AllocationBase: %p\n", MemBasicInfo->AllocationBase);

    wprintf (L"  AllocationProtect: %08X\n", MemBasicInfo->AllocationProtect);
    PRINT_MBI_BITMAP (i, PageProtections, MemBasicInfo->AllocationProtect);

    wprintf (L"         RegionSize: %08X (%u) bytes.\n",
             (ULONG) MemBasicInfo->RegionSize, (ULONG) MemBasicInfo->RegionSize);

    wprintf (L"              State: %08X\n", MemBasicInfo->State);
    PRINT_MBI_BITMAP (i, PageStates, MemBasicInfo->State);

    wprintf (L"            Protect: %08X\n", MemBasicInfo->Protect);
    PRINT_MBI_BITMAP (i, PageProtections, MemBasicInfo->Protect);

    wprintf (L"               Type: %08X\n", MemBasicInfo->Type);
    PRINT_MBI_BITMAP (i, PageTypes, MemBasicInfo->Type);

    return;
}

static VOID
QuerySnapshot (
    __in HPSS SnapshotHandle
    )

/*++

Routine Description:

    Queries the snapshot.

Arguments:

    SnapshotHandle - Specifies a handle the snapshot to query.

Return Value:

    None.

--*/

{
    DWORD rc;
    ULONG i;
    HPSSWALK WalkMarkerHandle;
    union {
        PSS_PROCESS_INFORMATION Process;
        PSS_PROCESS_INFORMATION_2 Process2;
        PSS_VA_CLONE_INFORMATION VaClone;
        PSS_AUXILIARY_PAGES_INFORMATION AuxPages;
        PSS_VA_SPACE_INFORMATION VaSpace;
        PSS_HANDLE_INFORMATION Handle;
        PSS_THREAD_INFORMATION Thread;
        PSS_HANDLE_TRACE_INFORMATION HandleTrace;
        PSS_PERFORMANCE_COUNTERS PerformanceCounters;

        PSS_AUXILIARY_PAGE_ENTRY AuxPageEntry;
        PSS_VA_SPACE_ENTRY VaSpaceEntry;
        PSS_HANDLE_ENTRY HandleEntry;
        PSS_THREAD_ENTRY ThreadEntry;
    } Buffer;

    MEMORY_BASIC_INFORMATION MemBasicInfo;


    //
    // Query snapshot: performance information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryPerformanceCounters,
                           &Buffer.PerformanceCounters,
                           sizeof (PSS_PERFORMANCE_COUNTERS));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryPerformanceCounters failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_PERFORMANCE_COUNTERS:\n"
                 L"TotalCycleCount: %I64u cycles.\n"
                 L"VaCloneCycleCount: %I64u cycles.\n"
                 L"VaSpaceCycleCount: %I64u cycles.\n"
                 L"AuxPagesCycleCount: %I64u cycles.\n"
                 L"HandlesCycleCount: %I64u cycles.\n"
                 L"ThreadsCycleCount: %I64u cycles.\n"
                 L"\n"
                 L"TotalWallClockPeriod: %I64u us.\n"
                 L"VaCloneWallClockPeriod: %I64u us.\n"
                 L"VaSpaceWallClockPeriod: %I64u us.\n"
                 L"AuxPagesWallClockPeriod: %I64u us.\n"
                 L"HandlesWallClockPeriod: %I64u us.\n"
                 L"ThreadsWallClockPeriod: %I64u us.\n\n",
                 Buffer.PerformanceCounters.TotalCycleCount,
                 Buffer.PerformanceCounters.VaCloneCycleCount,
                 Buffer.PerformanceCounters.VaSpaceCycleCount,
                 Buffer.PerformanceCounters.AuxPagesCycleCount,
                 Buffer.PerformanceCounters.HandlesCycleCount,
                 Buffer.PerformanceCounters.ThreadsCycleCount,
                 Buffer.PerformanceCounters.TotalWallClockPeriod,
                 Buffer.PerformanceCounters.VaCloneWallClockPeriod,
                 Buffer.PerformanceCounters.VaSpaceWallClockPeriod,
                 Buffer.PerformanceCounters.AuxPagesWallClockPeriod,
                 Buffer.PerformanceCounters.HandlesWallClockPeriod,
                 Buffer.PerformanceCounters.ThreadsWallClockPeriod);
    }

    //
    // Query snapshot: process information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryProcessInformation,
                           &Buffer.Process,
                           sizeof (PSS_PROCESS_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryProcessInformation with PSS_PROCESS_INFORMATION failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_PROCESS_INFORMATION:\n"
                 L"           Process ID: %4u (%4x)\n"
                 L"                 Path: %s\n"
                 L"        Base priority: %d %s.\n"
                 L"       Priority class: %08X %s.\n"
                 L"        Execute flags: %08X.\n"
                 L"   IsProtectedProcess: %u.\n"
                 L"       IsWow64Process: %u.\n"
                 L"    IsProcessDeleting: N/A.\n"
                 L" IsCrossSessionCreate: N/A.\n"
                 L"             IsFrozen: N/A.\n"
                 L"         IsBackground: N/A.\n"
                 L"      IsStronglyNamed: N/A.\n",
                 (ULONG) Buffer.Process.ProcessId,
                 (ULONG) Buffer.Process.ProcessId,
                 Buffer.Process.ImageFileName,
                 Buffer.Process.BasePriority,
                 LookupDictionary (Buffer.Process.BasePriority, PriorityValueDictionary),
                 Buffer.Process.PriorityClass,
                 LookupDictionary (Buffer.Process.PriorityClass, PriorityClassDictionary),
                 Buffer.Process.ExecuteFlags,
                 ((Buffer.Process.Flags & PSS_PROCESS_FLAGS_PROTECTED) ? 1 : 0),
                 ((Buffer.Process.Flags & PSS_PROCESS_FLAGS_WOW64) ? 1 : 0));
        wprintf (L"\n");
    }

    //
    // Query snapshot: process information v2.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryProcessInformation,
                           &Buffer.Process,
                           sizeof (PSS_PROCESS_INFORMATION_2));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryProcessInformation with PSS_PROCESS_INFORMATION_2 failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_PROCESS_INFORMATION_2:\n"
                 L"               Cookie: %08X.\n",
                 Buffer.Process2.Cookie);
        wprintf (L"\n");
    }

    //
    // Query snapshot: VA clone information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryVaCloneInformation,
                           &Buffer.VaClone,
                           sizeof (PSS_VA_CLONE_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryVaCloneInformation failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_VA_CLONE_INFORMATION:\n"
                 L"  VA clone process handle: %4X.\n\n",
                 (ULONG) Buffer.VaClone.VaCloneHandle);
    }

    //
    // Query snapshot: auxiliary page information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryAuxiliaryPagesInformation,
                           &Buffer.AuxPages,
                           sizeof (PSS_AUXILIARY_PAGES_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryAuxiliaryPagesInformation failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_AUXILIARY_PAGES_INFORMATION:\n"
                 L"  Auxiliary pages captured: %u.\n\n",
                 Buffer.AuxPages.AuxPagesCaptured);
    }

    //
    // Query snapshot: VA space information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryVaSpaceInformation,
                           &Buffer.VaSpace,
                           sizeof (PSS_VA_SPACE_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryVaSpaceInformation failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_VA_SPACE_INFORMATION:\n"
                 L"  Region count: %u.\n\n",
                 Buffer.VaSpace.RegionCount);
    }

    //
    // Query snapshot: handle information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryHandleInformation,
                           &Buffer.Handle,
                           sizeof (PSS_HANDLE_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryHandleInformation failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_HANDLE_INFORMATION:\n"
                 L"  Handles captured: %u.\n\n",
                 Buffer.Handle.HandlesCaptured);
    }

    //
    // Query snapshot: thread information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryThreadInformation,
                           &Buffer.Handle,
                           sizeof (PSS_THREAD_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryThreadInformation failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_THREAD_INFORMATION:\n"
                 L"  Threads captured: %u.\n"
                 L"    Context length: %u (0x%x) bytes.\n\n",
                 Buffer.Thread.ThreadsCaptured,
                 Buffer.Thread.ContextLength, Buffer.Thread.ContextLength);
    }

    //
    // Query snapshot: handle trace information.
    //
    rc = PssQuerySnapshot (SnapshotHandle,
                           PssQueryHandleTraceInformation,
                           &Buffer.HandleTrace,
                           sizeof (PSS_HANDLE_TRACE_INFORMATION));

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssQueryHandleTraceInformation failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }
    else {
        wprintf (L"PSS_HANDLE_TRACE_INFORMATION:\n"
                 L"  Section handle: %p.\n",
                 L"            Size: %4u bytes.\n\n",
                 Buffer.HandleTrace.SectionHandle,
                 Buffer.HandleTrace.Size);
    }

    //
    // Walk the snapshot: auxiliary pages.
    //
    rc = PssWalkMarkerCreate (NULL, &WalkMarkerHandle);
    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssWalkMarkerCreate failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    i = 0;
    rc = PssWalkSnapshot (SnapshotHandle,
                          PssWalkAuxiliaryPages,
                          WalkMarkerHandle,
                          &Buffer.AuxPageEntry,
                          sizeof (PSS_AUXILIARY_PAGE_ENTRY));

    wprintf (L"PSS_AUXILIARY_PAGE_ENTRY walk:\n");

    while (rc == ERROR_SUCCESS) {
        ++i;

        wprintf (L"  %2u) Auxiliary page %p of size: %u bytes.\n",
                 i,
                 Buffer.AuxPageEntry.Address,
                 Buffer.AuxPageEntry.PageSize);

        rc = PssWalkSnapshot (SnapshotHandle,
                              PssWalkAuxiliaryPages,
                              WalkMarkerHandle,
                              &Buffer.AuxPageEntry,
                              sizeof (PSS_AUXILIARY_PAGE_ENTRY));
    }

    if (rc == ERROR_NO_MORE_ITEMS) {
        wprintf (L"  Reached end of auxiliary page stream.\n\n");
    }
    else if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssWalkAuxiliaryPages failed: Win32 error %u (%s).\n\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    PssWalkMarkerFree (WalkMarkerHandle);

    //
    // Walk the snapshot: VA space.
    //
    rc = PssWalkMarkerCreate (NULL, &WalkMarkerHandle);
    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssWalkMarkerCreate failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    i = 0;
    rc = PssWalkSnapshot (SnapshotHandle,
                          PssWalkVaSpace,
                          WalkMarkerHandle,
                          &Buffer.VaSpaceEntry,
                          sizeof (PSS_VA_SPACE_ENTRY));

    wprintf (L"PSS_VA_SPACE_ENTRY walk:\n");

    while (rc == ERROR_SUCCESS) {
        ++i;

        wprintf (L"  %2u) Descriptor:\n", i);

        ZeroMemory (&MemBasicInfo, sizeof (MEMORY_BASIC_INFORMATION));
        MemBasicInfo.BaseAddress = Buffer.VaSpaceEntry.BaseAddress;
        MemBasicInfo.AllocationBase = Buffer.VaSpaceEntry.AllocationBase;
        MemBasicInfo.AllocationProtect = Buffer.VaSpaceEntry.AllocationProtect;
        MemBasicInfo.RegionSize = Buffer.VaSpaceEntry.RegionSize;
        MemBasicInfo.State = Buffer.VaSpaceEntry.State;
        MemBasicInfo.Protect = Buffer.VaSpaceEntry.Protect;
        MemBasicInfo.Type = Buffer.VaSpaceEntry.Type;

        PrintMemoryBasicInformation (&MemBasicInfo);
        wprintf (L"\n");

        wprintf (L"  SizeOfImage:%08X       ImageBase: %p\n"
                 L"    CheckSum: %08X   TimeDateStamp: %08X\n",
                 Buffer.VaSpaceEntry.SizeOfImage,
                 Buffer.VaSpaceEntry.ImageBase,
                 Buffer.VaSpaceEntry.CheckSum,
                 Buffer.VaSpaceEntry.TimeDateStamp);

        wprintf (L"                                        ");
        PrintUnixEpoch32 (Buffer.VaSpaceEntry.TimeDateStamp);
        wprintf (L"\n");

        if (Buffer.VaSpaceEntry.MappedFileNameLength) {
            //NT_ASSERT (Buffer.VaSpaceEntry.MappedFileName);
            wprintf (L"\n    Mapped file: %s\n", Buffer.VaSpaceEntry.MappedFileName);
        }

        wprintf (L"\n");

        rc = PssWalkSnapshot (SnapshotHandle,
                              PssWalkVaSpace,
                              WalkMarkerHandle,
                              &Buffer.VaSpaceEntry,
                              sizeof (PSS_VA_SPACE_ENTRY));
    }

    if (rc == ERROR_NO_MORE_ITEMS) {
        wprintf (L"  Reached end of VA space stream.\n\n");

    }
    else if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssWalkVaSpace failed: Win32 error %u (%s).\n\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    PssWalkMarkerFree (WalkMarkerHandle);

    //
    // Walk the snapshot: handles.
    //
    rc = PssWalkMarkerCreate (NULL, &WalkMarkerHandle);
    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssWalkMarkerCreate failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    i = 0;
    rc = PssWalkSnapshot (SnapshotHandle,
                          PssWalkHandles,
                          WalkMarkerHandle,
                          &Buffer.HandleEntry,
                          sizeof (PSS_HANDLE_ENTRY));

    wprintf (L"PSS_HANDLE_ENTRY walk:\n");

    while (rc == ERROR_SUCCESS) {
        ++i;
        wprintf (L"  %2u) Handle value: %4u (%4x)  %20s (%24s) %s\n",
                 i,
                 (ULONG) Buffer.HandleEntry.Handle,
                 (ULONG) Buffer.HandleEntry.Handle,
                 (Buffer.HandleEntry.TypeName ? Buffer.HandleEntry.TypeName : L"UNKNOWN"),
                 LookupDictionary (Buffer.HandleEntry.ObjectType, PssObjectTypes),
                 (Buffer.HandleEntry.ObjectName ? Buffer.HandleEntry.ObjectName : L"(nameless)"));

        switch (Buffer.HandleEntry.ObjectType) {
          case PSS_OBJECT_TYPE_EVENT:
            wprintf (L"       Event: ManualReset %u   Signaled %u\n",
                     Buffer.HandleEntry.TypeSpecificInformation.Event.ManualReset,
                     Buffer.HandleEntry.TypeSpecificInformation.Event.Signaled);
            break;
        }

        rc = PssWalkSnapshot (SnapshotHandle,
                              PssWalkHandles,
                              WalkMarkerHandle,
                              &Buffer.Handle,
                              sizeof (PSS_HANDLE_ENTRY));
    }

    if (rc == ERROR_NO_MORE_ITEMS) {
        wprintf (L"  Reached end of handle stream.\n\n");

    }
    else if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssWalkHandles failed: Win32 error %u (%s).\n\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    PssWalkMarkerFree (WalkMarkerHandle);

    //
    // Walk the snapshot: threads.
    //
    rc = PssWalkMarkerCreate (NULL, &WalkMarkerHandle);
    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssWalkMarkerCreate failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    i = 0;
    rc = PssWalkSnapshot (SnapshotHandle,
                          PssWalkThreads,
                          WalkMarkerHandle,
                          &Buffer.ThreadEntry,
                          sizeof (PSS_THREAD_ENTRY));

    wprintf (L"PSS_THREAD_ENTRY walk:\n");

    while (rc == ERROR_SUCCESS) {
        ++i;

        wprintf (L"  %2u) Thread ID: %4u (%4x)  suspend: %u  teb: %p  w32sa: %p  pc: %p  %s\n"
                 L"      priority %d (%s)    base priority %d (%s)\n",
                 i,
                 (ULONG) Buffer.ThreadEntry.ThreadId,
                 (ULONG) Buffer.ThreadEntry.ThreadId,
                 Buffer.ThreadEntry.SuspendCount,
                 Buffer.ThreadEntry.TebBaseAddress,
                 Buffer.ThreadEntry.Win32StartAddress,
                 (Buffer.ThreadEntry.ContextRecord ? CONTEXT_TO_PROGRAM_COUNTER (Buffer.ThreadEntry.ContextRecord) : 0xDEADBEEF),
                 ((Buffer.ThreadEntry.Flags & PSS_THREAD_FLAGS_TERMINATED) ? 1 : 0),
                 Buffer.ThreadEntry.Priority,
                 LookupDictionary (Buffer.ThreadEntry.Priority, PriorityValueDictionary),
                 Buffer.ThreadEntry.BasePriority,
                 LookupDictionary (Buffer.ThreadEntry.BasePriority, PriorityValueDictionary));

        rc = PssWalkSnapshot (SnapshotHandle,
                              PssWalkThreads,
                              WalkMarkerHandle,
                              &Buffer.Handle,
                              sizeof (PSS_THREAD_ENTRY));
    }

    if (rc == ERROR_NO_MORE_ITEMS) {
        wprintf (L"  Reached end of thread stream.\n\n");

    }
    else if (rc != ERROR_SUCCESS) {
        wprintf (L"PssQuerySnapshot/PssWalkThreads failed: Win32 error %u (%s).\n\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
    }

    PssWalkMarkerFree (WalkMarkerHandle);

    return;
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
    HANDLE ProcessHandle;
    HPSS SnapshotHandle;

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

            wprintf (L"Usage: psswin32.exe <process ID>\n");
            return 1;
        }

        ProcessHandle = OpenProcess (PROCESS_ALL_ACCESS,
                                     FALSE,
                                     _wtoi (argv[1]));
    }
    else {
        ProcessHandle = GetCurrentProcess ();
    }

    //
    // Snapshot the process.
    //
    rc = PssCaptureSnapshot (ProcessHandle,
                             CaptureFlags,
                             CONTEXT_ALL,
                             &SnapshotHandle);

    if (rc != ERROR_SUCCESS) {
        wprintf (L"PssCaptureSnapshot failed: Win32 error %u (%s).\n",
                 rc, LookupDictionary (rc, Win32ErrorCodes));
        return 1;
    }

    wprintf (L"Snapshot captured.\n");
    QuerySnapshot (SnapshotHandle);
    PssFreeSnapshot (GetCurrentProcess (), SnapshotHandle);

    return 0;
}
