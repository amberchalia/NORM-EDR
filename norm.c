#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

/*
 * Centralized logging macro.
 * Using INFO level because this is an observational / telemetry driver,
 * not an enforcement component yet.
 */
#define log(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, __VA_ARGS__)

/*
 * Configuration limits.
 * These bounds keep the prototype simple and predictable.
 */
#define max_slot 128          // Maximum number of tracked processes
#define max_dll 128           // Maximum static DLLs per process
#define max_dll_name 128      // Maximum DLL name length

/*
 * Baseline DLLs:
 * These are common OS / runtime libraries that are expected to load dynamically.
 * We suppress alerts for these to reduce noise.
 */
const char* base_dll[] =
{
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "ucrtbase.dll",
    "msvcrt.dll",
    "vcruntime140.dll",
    "user32.dll",
    "win32u.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "imm32.dll",
    "uxtheme.dll",
    "advapi32.dll",
    "sechost.dll",
    "rpcrt4.dll",
    "combase.dll",
    "clbcatq.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "kernel.appcore.dll"
};

#define base_dll_count (sizeof(base_dll) / sizeof(base_dll[0]))

/*
 * Check whether a DLL belongs to the baseline (noise suppression).
 */
BOOLEAN is_base_dll(_In_ PCCHAR dll_name) {
    for (ULONG i = 0; i < base_dll_count; i++) {
        if (_stricmp(dll_name, base_dll[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * Undocumented but stable helpers for PE parsing on mapped images.
 */
EXTERN_C
PIMAGE_NT_HEADERS
RtlImageNtHeader(_In_ PVOID base);

EXTERN_C
PIMAGE_IMPORT_DESCRIPTOR
RtlImageDirectoryEntryToData(
    _In_  PVOID   Base,
    _In_  BOOLEAN MappedAsImage,
    _In_  USHORT  DirectoryEntry,
    _Out_ PULONG  Size
);

/*
 * Per-process snapshot.
 * This is the core "entity" that the EDR reasons about.
 */
typedef struct _PS_SNAP
{
    HANDLE  pid;                                   // Process ID
    BOOLEAN in_use;                                // Slot allocation flag
    CHAR    static_dll_name[max_dll][max_dll_name];// Static import list
    ULONG   static_count;                          // Number of static DLLs
    BOOLEAN static_ready;                          // Static imports parsed
    BOOLEAN exe_seen;                              // Main EXE image observed
} ps_snap, *pps_snap;

/*
 * Global process table.
 * Indexed linearly for simplicity in this prototype.
 */
ps_snap table[max_slot];

/*
 * Allocate a process slot on process creation.
 */
pps_snap insert(_In_ HANDLE pid) {
    if (!pid)
        return NULL;

    for (ULONG i = 0; i < max_slot; i++) {
        if (!table[i].in_use) {
            RtlZeroMemory(&table[i], sizeof(ps_snap));
            table[i].in_use = TRUE;
            table[i].pid = pid;
            log("NORM: Slot %lu allocated for this PID: %lu\n", i, pid);
            return &table[i];
        }
    }
    log("NORM: No slot is avalable for PID: %lu\n", pid);
    return NULL;
}

/*
 * Free a process slot on process termination.
 */
void free_mem(_In_ HANDLE pid) {
    if (!pid)
        return;

    for (ULONG i = 0; i < max_slot; i++) {
        if (table[i].in_use && table[i].pid == pid) {
            RtlZeroMemory(&table[i], sizeof(ps_snap));
            log("NORM: slot: %lu is emptied for the PID: %lu\n", i, pid);
        }
    }
}

/*
 * Lookup process state by PID.
 */
pps_snap find_pid(_In_ HANDLE pid) {
    if (!pid)
        return NULL;

    for (ULONG i = 0; i < max_slot; i++) {
        if (table[i].in_use && table[i].pid == pid) {
            return &table[i];
        }
    }
    return NULL;
}

/*
 * Basic PE metadata extraction from disk.
 * Used for learning / inspection (not enforcement).
 */
typedef struct _PE_INFO
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  AddressOfEntryPoint;
    USHORT Subsystem;
    CHAR   section_name[9];
    BOOLEAN exec;
    BOOLEAN write;
    BOOLEAN ep_in_text;
} PE_INFO, *PPE_INFO;

/*
 * Parse PE headers directly from disk to inspect entry point and section flags.
 * This runs during process creation for visibility.
 */
BOOLEAN alpha(_In_ PCUNICODE_STRING image_path, _Out_ PPE_INFO pe_info) {
    OBJECT_ATTRIBUTES object;
    NTSTATUS status;
    HANDLE file = NULL;
    IO_STATUS_BLOCK io_status = { 0 };
    UCHAR buffer[1024] = { 0 };
    ULONG bytes = { 0 };

    InitializeObjectAttributes(
        &object,
        (PUNICODE_STRING)image_path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &file,
        GENERIC_READ,
        &object,
        &io_status,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        log("ZwCreateFile failed %X\n", status);
        return FALSE;
    }

    status = ZwReadFile(
        file,
        NULL,
        NULL,
        NULL,
        &io_status,
        &buffer,
        sizeof(buffer),
        NULL,
        NULL
    );

    ZwClose(file);

    if (!NT_SUCCESS(status))
        return FALSE;

    bytes = (ULONG)io_status.Information;

    if (bytes < 2 || buffer[0] != 'M' || buffer[1] != 'Z')
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buffer + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    pe_info->Machine = nt->FileHeader.Machine;
    pe_info->NumberOfSections = nt->FileHeader.NumberOfSections;
    pe_info->Subsystem = nt->OptionalHeader.Subsystem;
    pe_info->AddressOfEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;

    return TRUE;
}

/*
 * Check if a DLL was statically declared by the process.
 */
BOOLEAN is_static_dll(_In_ pps_snap ps, _In_ PCCHAR dll_name) {
    for (ULONG i = 0; i < ps->static_count; i++) {
        if (_stricmp(ps->static_dll_name[i], dll_name) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * Extract DLL name from a full image path.
 * Normalizes to lowercase for comparison.
 */
BOOLEAN extract_dll_name(
    _In_ PUNICODE_STRING full_path,
    _Out_ CHAR* name,
    _In_ ULONG size
) {
    if (!full_path || !full_path->Buffer || size == 0)
        return FALSE;

    PWCHAR buf = full_path->Buffer;
    ULONG len = full_path->Length / sizeof(WCHAR);

    LONG i;
    for (i = len - 1; i >= 0; i--) {
        if (buf[i] == L'\\')
            break;
    }

    PWCHAR dll_name_w = (i >= 0) ? &buf[i + 1] : buf;

    UNICODE_STRING us;
    ANSI_STRING as;

    RtlInitUnicodeString(&us, dll_name_w);
    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&as, &us, TRUE)))
        return FALSE;

    RtlZeroMemory(name, size);
    strncpy(name, as.Buffer, size - 1);
    RtlFreeAnsiString(&as);

    for (ULONG j = 0; name[j]; j++) {
        if (name[j] >= 'A' && name[j] <= 'Z')
            name[j] += 32;
    }
    return TRUE;
}

/*
 * Parse static imports from the main executable image.
 * This establishes the process baseline.
 */
BOOLEAN alpha_image(_In_ PVOID base, _In_ SIZE_T size, _In_ pps_snap ps) {
    if (!base || size == 0)
        return FALSE;

    PIMAGE_NT_HEADERS nt = RtlImageNtHeader(base);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    ULONG dir_size = 0;
    PIMAGE_IMPORT_DESCRIPTOR imp =
        RtlImageDirectoryEntryToData(
            base,
            TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            &dir_size
        );

    if (!imp || dir_size == 0)
        return FALSE;

    PUCHAR start = (PUCHAR)base;
    PUCHAR end = start + size;

    for (; imp->Name && ps->static_count < max_dll; imp++) {
        PUCHAR dll_name = start + imp->Name;
        if (dll_name < start || dll_name > end)
            continue;

        strncpy(ps->static_dll_name[ps->static_count],
                (PCHAR)dll_name,
                max_dll_name - 1);
        ps->static_dll_name[ps->static_count][max_dll_name - 1] = '\0';
        ps->static_count++;
    }

    ps->static_ready = TRUE;
    log("NORM: PID: %lu have %lu DLLS\n", ps->pid, ps->static_count);
    return TRUE;
}

/*
 * Image load notification.
 * Correlates runtime DLL loads against static baseline.
 */
void notify_image(
    _In_opt_ PUNICODE_STRING image_name,
    _In_ HANDLE process_id,
    _In_ PIMAGE_INFO image_info
) {
    if (image_info->SystemModeImage)
        return;

    pps_snap ps = find_pid(process_id);
    if (!ps)
        return;

    /* First user-mode image = main EXE */
    if (!ps->exe_seen) {
        ps->exe_seen = TRUE;
        alpha_image(image_info->ImageBase, image_info->ImageSize, ps);
        return;
    }

    if (!ps->static_ready)
        return;

    CHAR dll_name[max_dll_name] = { 0 };
    if (!extract_dll_name(image_name, dll_name, sizeof(dll_name)))
        return;

    if (!is_static_dll(ps, dll_name) && !is_base_dll(dll_name)) {
        log("[ALERT] PID: %lu loaded UNDECLARED DLL: %s\n",
            process_id, dll_name);
    }
}

/*
 * Process lifecycle notification.
 * Allocates and frees per-process state.
 */
void notify(
    _In_ PEPROCESS process,
    _In_ HANDLE process_id,
    _In_opt_ PPS_CREATE_NOTIFY_INFO info
) {
    UNREFERENCED_PARAMETER(process);

    if (info) {
        log("\n================ PROCESS CREATE ================\n");
        if (info->ImageFileName && info->ImageFileName->Buffer) {
            log("PID: %lu\nImage: %wZ\n", process_id, info->ImageFileName);
        }
        insert(process_id);
    } else {
        log("\n================ PROCESS EXIT ==================\n");
        free_mem(process_id);
    }
}

/*
 * Driver unload routine.
 */
void unload(IN PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    PsSetCreateProcessNotifyRoutineEx(notify, TRUE);
    PsRemoveLoadImageNotifyRoutine(notify_image);
    log("NORM: UNLOADED SUCCESSFULLY!");
}

/*
 * Driver entry point.
 */
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver_object, IN PUNICODE_STRING rs)
{
    UNREFERENCED_PARAMETER(rs);

    RtlZeroMemory(&table, sizeof(table));

    PsSetCreateProcessNotifyRoutineEx(notify, FALSE);
    PsSetLoadImageNotifyRoutine(notify_image);

    driver_object->DriverUnload = unload;
    log("NORM: LOADED SUCCESSFULLY!");
    return STATUS_SUCCESS;
}
