package main

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func main() {
	content, err := ioutil.ReadFile(`d:\KubeArmor\policies\block-dll.yaml`)
	if err != nil {
		fmt.Println("ReadFile error:", err)
		return
	}

	var policy tp.HostSecurityPolicy
	err = yaml.Unmarshal(content, &policy)
	if err != nil {
		fmt.Println("Unmarshal error:", err)
		return
	}

	fmt.Printf("Parsed Policy Action: %q\n", policy.Spec.Action)
	fmt.Printf("MatchPaths count: %d\n", len(policy.Spec.Process.MatchPaths))
	for _, p := range policy.Spec.Process.MatchPaths {
		fmt.Printf("  Path: %q, Action: %q\n", p.Path, p.Action)
		ext := filepath.Ext(strings.ToLower(string(p.Path)))
		fmt.Printf("  Ext: %q\n", ext)
	}
}
