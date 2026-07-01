//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	"sync"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"golang.org/x/sys/windows"
)

var (
	_ RuntimeEnforcer = (*RuntimeEnforcerImpl)(nil)
)

// RuntimeEnforcerImpl Structure
type RuntimeEnforcerImpl struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string

	// Driver device handle for IOCTL communication
	deviceHandle windows.Handle

	// Mutex for serializing policy updates
	mu sync.Mutex
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(node tp.Node, logger *fd.Feeder, monitor *mon.SystemMonitor) RuntimeEnforcer {
	re := &RuntimeEnforcerImpl{}
	re.Logger = logger
	re.EnforcerType = "Minifilter"
	re.deviceHandle = windows.InvalidHandle

	// Attempt to open the Karmor driver device for IOCTL communication.
	// If the driver is not loaded, enforcement is disabled but monitoring
	// (via FltMgr communication port) still works.
	handle, err := openDriverDevice()
	if err != nil {
		logger.Errf("Failed to open Karmor driver device: %v (file enforcement disabled)", err)
	} else {
		re.deviceHandle = handle
		logger.Printf("Karmor driver device opened successfully for enforcement")
	}

	logger.UpdateEnforcer(re.EnforcerType)
	return re
}

func (re *RuntimeEnforcerImpl) GetEnforcerType() string {
	return re.EnforcerType
}

// RegisterContainer registers container identifiers to BPFEnforcer Map
func (re *RuntimeEnforcerImpl) RegisterContainer(containerID string, pidns, mntns uint32) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UnregisterContainer removes container identifiers from BPFEnforcer Map
func (re *RuntimeEnforcerImpl) UnregisterContainer(containerID string) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateAppArmorProfiles Function
func (re *RuntimeEnforcerImpl) UpdateAppArmorProfiles(podName string, action string, profiles map[string]string, privilegedProfiles map[string]struct{}) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcerImpl) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateHostSecurityPolicies translates KubeArmor host security policies
// into driver-level rules and sends them to the Karmor minifilter via IOCTL.
//
// This uses a clear-and-reload strategy: all existing rules in the driver are
// cleared first, then the full policy set is re-sent. This is simple and
// correct, with a brief enforcement gap during the reload.
func (re *RuntimeEnforcerImpl) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	// skip if driver device is not open
	if re.deviceHandle == windows.InvalidHandle {
		return
	}
	re.Logger.Printf("Device Handle: %+v \n", re.deviceHandle)

	re.mu.Lock()
	defer re.mu.Unlock()

	// Step 1: Clear all existing rules in the driver
	if err := sendIoctl(re.deviceHandle, ioctlClearRules, nil); err != nil {
		re.Logger.Errf("Failed to clear rules in driver: %v", err)
		return
	}

	fileRuleCount := 0
	processRuleCount := 0

	// Step 2: Send new rules from each policy
	for _, policy := range secPolicies {
		re.Logger.Printf("Processing policy: %+v", policy)
		defaultAction := mapActionString(policy.Spec.Action)

		// === File matchPaths ===
		for _, fp := range policy.Spec.File.MatchPaths {
			action := resolveAction(fp.Action, defaultAction)
			flags := uint16(0)
			if fp.ReadOnly {
				flags |= ruleFlagReadOnly
			}

			ntPath, err := convertToNTPath(fp.Path)
			if err != nil {
				re.Logger.Errf("Path conversion failed for %s: %v", fp.Path, err)
				continue
			}

			req, err := buildRuleRequest(ruleTypeFile, matchPath, action, flags, ntPath)
			if err != nil {
				re.Logger.Errf("Failed to build rule request for %s: %v", fp.Path, err)
				continue
			}

			if err := sendIoctl(re.deviceHandle, ioctlAddRule, req); err != nil {
				re.Logger.Errf("Failed to send file rule for %s: %v", fp.Path, err)
				continue
			}

			fileRuleCount++
		}

		// === File matchDirectories (Phase 2 — log warning) ===
		for _, dp := range policy.Spec.File.MatchDirectories {
			re.Logger.Warnf("matchDirectories not yet supported on Windows, skipping: %s", dp.Directory)
		}

		// === Process matchPaths ===
		for _, pp := range policy.Spec.Process.MatchPaths {
			action := resolveAction(pp.Action, defaultAction)

			ntPath, err := convertToNTPath(pp.Path)
			if err != nil {
				re.Logger.Errf("Path conversion failed for %s: %v", pp.Path, err)
				continue
			}

			req, err := buildRuleRequest(ruleTypeProcess, matchPath, action, 0, ntPath)
			if err != nil {
				re.Logger.Errf("Failed to build rule request for %s: %v", pp.Path, err)
				continue
			}

			if err := sendIoctl(re.deviceHandle, ioctlAddRule, req); err != nil {
				re.Logger.Errf("Failed to send process rule for %s: %v", pp.Path, err)
				continue
			}

			processRuleCount++
		}
	}

	re.Logger.Printf("Policy update complete: %d file rules, %d process rules sent to driver",
		fileRuleCount, processRuleCount)
}

// resolveAction determines the effective action for a rule.
// If the rule has its own action, use it; otherwise fall back to the policy default.
func resolveAction(ruleAction string, defaultAction int16) int16 {
	if ruleAction != "" {
		return mapActionString(ruleAction)
	}
	return defaultAction
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcerImpl) DestroyRuntimeEnforcer() error {
	// skip if runtime enforcer is not active
	if re == nil {
		return nil
	}

	if re.deviceHandle != 0 && re.deviceHandle != windows.InvalidHandle {
		// Clear all rules before disconnecting so enforcement stops cleanly
		if err := sendIoctl(re.deviceHandle, ioctlClearRules, nil); err != nil {
			re.Logger.Errf("Failed to clear rules during shutdown: %v", err)
		}
		windows.CloseHandle(re.deviceHandle)
		re.deviceHandle = windows.InvalidHandle
		re.Logger.Printf("Karmor driver device closed, enforcement stopped")
	}

	return nil
}
