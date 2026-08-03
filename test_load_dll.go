package main
import (
	"fmt"
	"golang.org/x/sys/windows"
)
func main() {
	dllPath := `D:\KubeArmor\policies\test-files\malicious.dll`
	handle, err := windows.LoadLibrary(dllPath)
	if err != nil {
		fmt.Printf("LoadLibrary Failed! Error: %v\n", err)
	} else {
		fmt.Printf("LoadLibrary Succeeded! Handle: %v\n", handle)
		windows.FreeLibrary(handle)
	}
}
