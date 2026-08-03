package main

import (
	"fmt"
	"unsafe"
	"golang.org/x/sys/windows"
)

const (
	ioctlAddRule = 0x8022A000
)

type userRuleRequest struct {
	RuleType  uint16
	MatchType uint16
	Action    int16
	Flags     uint16
	Path      [520]uint16
}

func main() {
	path, err := windows.UTF16PtrFromString(`\\.\Karmor`)
	if err != nil {
		fmt.Println("UTF16PtrFromString error:", err)
		return
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		fmt.Println("CreateFile Karmor error:", err)
		return
	}
	defer windows.CloseHandle(handle)

	var req userRuleRequest
	req.RuleType = 1 // RULE_TYPE_FILE
	req.MatchType = 1 // MATCH_PATH
	req.Action = 1 // Block
	req.Flags = 0

	ntPath := `\Device\HarddiskVolume4\KubeArmor\policies\test-files\malicious.dll`
	pathUTF16, _ := windows.UTF16FromString(ntPath)
	copy(req.Path[:], pathUTF16)

	var bytesReturned uint32
	err = windows.DeviceIoControl(handle, ioctlAddRule, (*byte)(unsafe.Pointer(&req)), uint32(unsafe.Sizeof(req)), nil, 0, &bytesReturned, nil)
	if err != nil {
		fmt.Println("DeviceIoControl AddRule error:", err)
		return
	}

	fmt.Println("Rule added successfully!")
}
