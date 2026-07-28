<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# there is a problem. we need logic to convert Win32 file paths to kernel NT namespace paths.

Take this scenario, if we want user to block file access via applying a policy like we do in kubearmor for linux, user will give the Win32 address. we need some method to convert this file path to NT namespace. as the kernel only sees NT paths(if that is true)

Check how we can do that as we need this utility in a bigger driver so we can test it in this small poc.
It should be performant and reliable and you can check other projects as well.

You’re right that you need a bridge: policies will be in Win32 (DOS) format like `C:\foo\bar.txt`, while your minifilter sees NT-style names like `\Device\HarddiskVolume3\foo\bar.txt` (or sometimes `\??\C:\foo\bar.txt`).[^1][^2]
The usual pattern is: convert the DOS path to a *canonical NT device path* once (outside the hot path), then compare that to the normalized name you get from `FltGetFileNameInformation` in your pre‑create callback.[^3][^4]

## High‑level approach

- Keep policies in a canonical format that matches what `FltGetFileNameInformation(..., FLT_FILE_NAME_NORMALIZED)` returns: `\Device\XXX\path\to\file` or `\??\C:\path\to\file` depending on OS/version.[^2][^1]
- When the user gives you a Win32 path (`C:\foo\bar.txt`), convert it *once* to a `UNICODE_STRING` in that canonical NT namespace (e.g. `\Device\HarddiskVolume3\foo\bar.txt`) and store it in your driver’s policy table.[^5][^3]
- In `PtPreOperationPassThrough` for `IRP_MJ_CREATE`, call `FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)`, then `FltParseFileNameInformation`, and compare `nameInfo->Name` against your pre‑converted policy entries using `RtlEqualUnicodeString`/`RtlPrefixUnicodeString` (case‑insensitive).[^1][^2][^6]

This way the NT conversion cost is paid only when policies change, not on every I/O, so it’s both performant and reliable.

## Converting Win32 `C:\path` to NT device path in the driver

A solid, commonly used approach (described in Pavel Yosifovich’s *Windows Kernel Programming* minifilter samples) is to resolve the drive letter via the `\??\X:` symbolic link and build a full NT path:[^3]

1. Validate input is of the form `X:\something` (drive letter, colon, backslash). Reject malformed or relative paths.[^3]
2. Build the symbolic link name `\??\X:` as a `UNICODE_STRING`.
3. `ZwOpenSymbolicLinkObject` on that name to get a handle.
4. `ZwQuerySymbolicLinkObject` to read the link target, which is the NT device name, e.g. `\Device\HarddiskVolume3`.[^3]
5. Allocate an output `UNICODE_STRING` big enough for: target device name + rest of original path (starting at the backslash after `X:`).
6. Copy the device name, then append the path part; the result is something like `\Device\HarddiskVolume3\foo\bar.txt`.
7. Close the symbolic link handle and return the NT name.

A sketch in kernel C (heavily simplified and paraphrased from the book code):[^3]

```c
NTSTATUS
ConvertDosNameToNtName(
    _In_ PCWSTR DosName,      // e.g. L"C:\\foo\\bar.txt"
    _Out_ PUNICODE_STRING NtName // allocated on success, caller frees with ExFreePool
)
{
    NTSTATUS status;
    UNICODE_STRING symLinkName;
    HANDLE hSymLink = NULL;
    OBJECT_ATTRIBUTES oa;
    WCHAR linkBuf[^64];
    UNICODE_STRING target = {0};

    NtName->Buffer = NULL;
    NtName->Length = NtName->MaximumLength = 0;

    size_t len = wcslen(DosName);
    if (len < 3 || DosName[^1] != L':' || DosName[^2] != L'\\')
        return STATUS_INVALID_PARAMETER; // only X:\... for now

    // Build "\??\X:"
    swprintf(linkBuf, L"\\??\\%c:", DosName[^0]);
    RtlInitUnicodeString(&symLinkName, linkBuf);

    InitializeObjectAttributes(&oa, &symLinkName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&hSymLink, GENERIC_READ, &oa);
    if (!NT_SUCCESS(status))
        return status;

    // Query target device name into 'target' (allocate buffer from paged pool)
    // ZwQuerySymbolicLinkObject(&hSymLink, &target, NULL);

    // Allocate NtName buffer: target + path part (DosName + 2 -> skip "X:")
    // Build "\Device\HarddiskVolume3\foo\bar.txt" into NtName

    // Cleanup
    if (hSymLink)
        ZwClose(hSymLink);

    if (!NT_SUCCESS(status) && NtName->Buffer) {
        ExFreePool(NtName->Buffer);
        NtName->Buffer = NULL;
    }
    return status;
}
```

The real code must handle allocation, error paths, and `ZwQuerySymbolicLinkObject` buffer sizing properly, but this is the core idea.[^3]
This is exactly how that sample driver keeps an internal list of *protected directories* in NT form while the user configures them via DOS paths.[^3]

## Why not just use `RtlDosPathNameToNtPathName_U`?

- `RtlDosPathNameToNtPathName_U` / `_WithStatus` live in `ntdll.dll` and are formally user‑mode APIs; the docs explicitly describe calling them via `LoadLibrary/GetProcAddress` in user space and do not provide a kernel import.[^7][^8][^9]
- In kernel you’d have to rely on an internal, unsupported export; that’s fragile and not recommended for a production‑quality driver.

If you *do* have a user‑mode service in your architecture (which you probably will for policy management), you can use these functions there:

```c
NTSTATUS RtlDosPathNameToNtPathName_U_WithStatus(
    PCWSTR DosFileName,
    PUNICODE_STRING NtFileName,
    PWSTR *FilePart,
    PVOID Reserved
);
```

They convert DOS paths (`C:\...`, `\\server\share\...`, `\\?\...`) into a Win32‑style NT path (`\??\C:\...`, `\Device\Mup\...`), which you can then send to the driver as already‑canonicalized policy data.[^8][^10][^7]

## Recommended architecture for your bigger driver

Given what you want (Kubearmor‑style policies, but on Windows), I’d suggest:

- **User‑mode side (policy CLI / service):**
    - Accept user paths (`C:\foo\bar.py` etc.).
    - Canonicalize them: `GetFullPathNameW` / `GetLongPathNameW` to remove `.`/`..` and 8.3 short names.[^4][^10]
    - Convert to NT path using `RtlDosPathNameToNtPathName_U_WithStatus`.
    - Optionally, normalize drive letters and handle UNC vs local consistently.
    - Send the resulting NT path string to the driver via IOCTL (along with action: block/allow, etc.).
- **Kernel minifilter:**
    - Store the NT paths as `UNICODE_STRING`s in a policy structure (array, RB‑tree, or hash keyed by `volume+path`).
    - On `IRP_MJ_CREATE`, get `nameInfo` via `FltGetFileNameInformation(..., FLT_FILE_NAME_NORMALIZED)`, parse with `FltParseFileNameInformation`, then compare `nameInfo->Name` to entries in your policy table (exact match, prefix match, glob, whatever semantics you want).[^1][^4][^2]
    - If match → set `Data->IoStatus.Status = STATUS_ACCESS_DENIED` and return `FLT_PREOP_COMPLETE` as you already do in your POC.[^6]

Performance‑wise, this is good: `FltGetFileNameInformation` uses the filter manager’s name cache and is the recommended way to get normalized names, and you only do path conversion in user mode or once per policy update, not per I/O.[^11][^2][^1]

## Testing this in your current POC

To integrate this into your existing `passThrough.c`‑based POC:[^6]

- Add a simple IOCTL interface that lets a user‑mode test program send you a list of NT‑style paths to block.
- In the test program:
    - Take user input (`C:\something\6.py`), convert it to NT path using `RtlDosPathNameToNtPathName_U_WithStatus`, and pass that string down.[^7][^8]
- In `PtPreOperationPassThrough`, instead of hardcoding `"6.py"` as a suffix, compare `nameInfo->Name` against your stored NT path(s). If equal, deny the create as you already do.[^6][^3]

If you want, share how you’re planning to flow policies (IOCTL format, per‑file vs per‑dir), and I can help you sketch the structs and comparison logic to keep this fast (e.g., per‑volume prefix lists rather than linear scans).
<span style="display:none">[^12][^13][^14][^15][^16]</span>

<div align="center">⁂</div>

[^1]: https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/ifs/managing-file-names.md

[^2]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgetfilenameinformation

[^3]: https://pubhtml5.com/dtiq/ufpk/basic/301-350

[^4]: https://www.apriorit.com/dev-blog/675-driver-windows-minifilter-driver-development-tutorial

[^5]: https://community.osr.com/t/dealing-with-files-in-both-user-mode-and-kernel/38943

[^6]: passThrough.c

[^7]: https://learn.microsoft.com/en-us/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus

[^8]: https://learn.microsoft.com/ru-ru/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus

[^9]: https://learn.microsoft.com/ko-kr/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus

[^10]: https://de.scribd.com/document/102810219/Long-Paths

[^11]: http://fsfilters.blogspot.com/2011/06/

[^12]: https://stackoverflow.com/questions/29796200/get-file-path-in-minifilter-driver

[^13]: https://stackoverflow.com/questions/45361494/how-to-get-file-name-safetly-and-compare-it-in-windows-minifilter-driver

[^14]: https://learn.microsoft.com/zh-cn/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus

[^15]: https://www.reddit.com/r/programming/comments/12u9giq/the_weird_world_of_windows_file_paths/

[^16]: https://community.osr.com/t/converting-path-names/43039

