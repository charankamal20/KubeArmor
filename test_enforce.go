package main

import (
	"fmt"
	"io/ioutil"
	"unsafe"
	"encoding/json"

	"sigs.k8s.io/yaml"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
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
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 2) // VOLUME_NAME_NT
	if err != nil {
		return "", fmt.Errorf("GetFinalPathNameByHandle: %w", err)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func main() {
	content, _ := ioutil.ReadFile(`d:\KubeArmor\policies\block-dll.yaml`)
	jsonData, _ := yaml.YAMLToJSON(content)
	var policy tp.HostSecurityPolicy
	json.Unmarshal(jsonData, &policy)

	pathPtr, _ := windows.UTF16PtrFromString(`\\.\Karmor`)
	h, err := windows.CreateFile(pathPtr, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		fmt.Println("CreateFile error:", err)
		return
	}
	defer windows.CloseHandle(h)

	for _, pp := range policy.Spec.Process.MatchPaths {
		pathStr := string(pp.Path)
		ntPath, err := ntPathFromHandle(pathStr)
		if err != nil {
			fmt.Println("ntPath error:", err)
			continue
		}
		
		var req userRuleRequest
		req.RuleType = 1
		req.MatchType = 1
		req.Action = 1
		pathUTF16, _ := windows.UTF16FromString(ntPath)
		copy(req.Path[:], pathUTF16)

		var bytesReturned uint32
		err = windows.DeviceIoControl(h, ioctlAddRule, (*byte)(unsafe.Pointer(&req)), uint32(unsafe.Sizeof(req)), nil, 0, &bytesReturned, nil)
		if err != nil {
			fmt.Println("DeviceIoControl error:", err)
		}
		fmt.Printf("Added: %s -> %s\n", pathStr, ntPath)
	}
}
