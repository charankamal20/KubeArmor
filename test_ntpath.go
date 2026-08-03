package main

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func ntPathFromHandle(dosPath string) (string, error) {
	pathPtr, err := windows.UTF16PtrFromString(dosPath)
	if err != nil {
		return "", fmt.Errorf("UTF-16 conversion: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("CreateFile: %w", err)
	}
	defer windows.CloseHandle(handle)

	var buf [1024]uint16
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), windows.VOLUME_NAME_NT)
	if err != nil {
		return "", fmt.Errorf("GetFinalPathNameByHandle: %w", err)
	}

	if n > uint32(len(buf)) {
		return "", fmt.Errorf("buffer too small, needed %d", n)
	}

	return windows.UTF16ToString(buf[:n]), nil
}

func main() {
	p, err := ntPathFromHandle(`D:\KubeArmor\policies\test-files\malicious.dll`)
	fmt.Println(p, err)
}
