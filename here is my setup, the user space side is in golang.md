<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# here is my setup, the user space side is in golang, KubeArmor project is the user space.

Nice, that actually makes your life easier: all the “DOS → NT” work can live in Go in KubeArmor, and the driver only ever sees canonical NT paths.

## What to do in Go

On the KubeArmor (Go) side, when a policy contains something like `C:\foo\bar.py`:

1. Canonicalize to an absolute, long path (e.g. using `GetFullPathNameW` via `x/sys/windows`).
2. Convert that DOS/Win32 path to an NT path using `RtlDosPathNameToNtPathName_U_WithStatus` from `ntdll.dll` (user‑mode API).[^1][^2]
3. Send that NT path string down to your minifilter via IOCTL.
4. In the driver, store the NT paths as `UNICODE_STRING`s and compare them against `FltGetFileNameInformation(..., FLT_FILE_NAME_NORMALIZED)` → `nameInfo->Name` in your pre‑create path.

That keeps your kernel code simple and avoids re‑implementing DOS‑path parsing there.

## Calling `RtlDosPathNameToNtPathName` from Go

You can access `ntdll.dll` from Go via `golang.org/x/sys/windows` (it already loads `ntdll` lazily), or you can use a helper package like `github.com/hillu/go-ntdll` that exposes `RtlDosPathNameToNtPathName_U` directly.[^3][^4]

Rough outline using `x/sys/windows`:

- Load `ntdll.dll` with `windows.NewLazySystemDLL("ntdll.dll")`.
- Get the proc `RtlDosPathNameToNtPathName_U_WithStatus` using `NewProc`.
- Define a Go struct that matches `UNICODE_STRING`.
- Call the proc via `syscall.SyscallN` (or the wrapped `Proc.Call`), passing the DOS path (`*uint16`) and a pointer to your `UNICODE_STRING`.[^5][^6][^1]

There’s even a Go CL discussion that wires this exact function: they declare

```go
//sys RtlDosPathNameToNtPathName(dosName *uint16, ntName *NTUnicodeString, ntFileNamePart *uint16, relativeName *RTL_RELATIVE_NAME) (ntstatus error) = ntdll.RtlDosPathNameToNtPathName_U_WithStatus
```

which is exactly the mapping you want, just with Go’s syscall generator.[^5]

If you prefer not to hand‑roll the syscall at all, `github.com/hillu/go-ntdll` already exposes:

- `func RtlDosPathNameToNtPathName_U(DosFileName *uint16, NtFileName *UnicodeString, FilePart *uint16, ...) bool`[^3]

so in KubeArmor you can:

- Convert the Go `string` path to UTF‑16 (`windows.UTF16PtrFromString`).
- Call `ntdll.RtlDosPathNameToNtPathName_U`.
- Convert the returned `UNICODE_STRING.Buffer` (UTF‑16) back to Go `string` and send that down to the driver as your canonical NT policy path.


## Alternative (if you avoid `ntdll`)

If you ever decide you don’t want to rely on `ntdll` from Go, another option is:

- `CreateFileW` the DOS path.
- Use `GetFinalPathNameByHandleW` with `FILE_NAME_NORMALIZED | VOLUME_NAME_NT` to get the NT‑style path like `\Device\HarddiskVolume3\foo\bar.py`. [^7][^8][^9]

This is a bit heavier (requires opening the file) but still fine for policy configuration, not per‑I/O.

If you show me a small Go snippet from KubeArmor where you’d like to plug this in, I can write the concrete `RtlDosPathNameToNtPathName_U_WithStatus` wrapper in Go that returns a clean `string` you can shove into your policy structs.
<span style="display:none">[^10][^11][^12][^13][^14][^15]</span>

<div align="center">⁂</div>

[^1]: https://learn.microsoft.com/en-us/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus

[^2]: https://learn.microsoft.com/zh-cn/windows/win32/devnotes/rtldospathnametontpathname_u_withstatus

[^3]: https://pkg.go.dev/github.com/hillu/go-ntdll

[^4]: https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go

[^5]: https://groups.google.com/g/golang-codereviews/c/z-3fMktzFV4

[^6]: https://go.dev/wiki/WindowsDLLs

[^7]: https://stackoverflow.com/questions/58679897/how-can-i-get-the-current-directory-with-correct-spelling

[^8]: https://espresso3389.hatenablog.com/entry/20080212/1202808319

[^9]: https://qiita.com/AsladaGSX/items/1f2f2117e126963d83d5

[^10]: https://chromium.googlesource.com/external/github.com/microsoft/go-winio/+/5adf6781fa9ee8fc748d8cd8e2a8dc7ac3fabf14/zsyscall_windows.go

[^11]: https://golang.google.cn/src/syscall/dll_windows.go?m=text

[^12]: https://community.osr.com/t/ntdll-dll/31789

[^13]: https://stackoverflow.com/questions/50177926/how-does-one-use-getfinalpathnamebyhandle-to-resolve-a-symbolic-link-to-a-local

[^14]: https://leandrofroes.github.io/posts/An-in-depth-look-at-Golang-Windows-calls/

[^15]: https://forums.passmark.com/osforensics-osfmount-osfclone/49217-win32-api-function-getfinalpathnamebyhandlew-fails-on-volume-mounted-by-osfmount

