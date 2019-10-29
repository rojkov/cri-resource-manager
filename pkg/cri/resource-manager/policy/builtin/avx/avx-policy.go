// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package avx

import (
	"sync"
	"time"

	avx512 "github.com/intel/cri-resource-manager/pkg/avx"
	"github.com/intel/cri-resource-manager/pkg/cri/resource-manager/cache"
	"github.com/intel/cri-resource-manager/pkg/cri/resource-manager/policy"
	logger "github.com/intel/cri-resource-manager/pkg/log"
	"github.com/intel/cri-resource-manager/pkg/sysfs"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	// PolicyName is the symbol used to pull us in as a builtin policy.
	PolicyName = "avx"
	// PolicyDescription is a short description of this policy.
	PolicyDescription = "An AVX512 aware policy assigning containers using AVX512 to dedicated cores."

	// TODO: make it configurable
	cgroupRoot  = "/sys/fs/cgroup/unified"
	ebpfElfPath = "/home/rojkov/work/cri-resource-manager/libexec/avx512.o"
)

type avx struct {
	logger.Logger
	sync.Mutex

	ticker         *time.Ticker
	metricFamilies []*dto.MetricFamily
	sys            *sysfs.System // system/topology information
}

func createPolicy(opts *policy.BackendOptions) policy.Backend {
	a := &avx{
		Logger: logger.NewLogger(PolicyName),
		ticker: time.NewTicker(5 * time.Second),
	}
	a.Info("creating policy...")

	collector, err := avx512.NewCollector(cgroupRoot, ebpfElfPath)
	if err != nil {
		a.Fatal("unable to create Prometheus collector: %+v", err)
	}
	gatherer := prometheus.NewRegistry()
	if err := gatherer.Register(collector); err != nil {
		a.Fatal("unable to register Prometheus collector: %+v", err)
	}

	sys, err := sysfs.DiscoverSystem()
	if err != nil {
		a.Fatal("failed to discover system topology: %v", err)
	}

	a.sys = sys

	go func() {
		for range a.ticker.C {
			metricFamilies, err := gatherer.Gather()
			if err != nil {
				a.Error("unable to gather metrics: %+v", err)
			}
			a.Lock()
			a.metricFamilies = metricFamilies
			a.Unlock()
			a.Debug("refreshed metrics: %+v", metricFamilies)
			a.Debug("CPUs: %+v", sys.CPUSet())
		}
	}()

	return a
}

// Name returns the name of this policy.
func (a *avx) Name() string {
	return PolicyName
}

// Description returns the description for this policy.
func (a *avx) Description() string {
	return PolicyDescription
}

// Start prepares this policy for accepting allocation/release requests.
func (a *avx) Start(cch cache.Cache, add []cache.Container, del []cache.Container) error {
	a.Debug("got started...")
	return nil
}

// Sync synchronizes the active policy state.
func (a *avx) Sync(add []cache.Container, del []cache.Container) error {
	a.Debug("(not) synchronizing policy state")
	return nil
}

// AllocateResources is a resource allocation request for this policy.
func (a *avx) AllocateResources(c cache.Container) error {
	a.Debug("(not) allocating container %s...", c.PrettyName())
	return nil
}

// ReleaseResources is a resource release request for this policy.
func (a *avx) ReleaseResources(c cache.Container) error {
	a.Debug("(not) releasing container %s...", c.PrettyName())
	return nil
}

// UpdateResources is a resource allocation update request for this policy.
func (a *avx) UpdateResources(c cache.Container) error {
	a.Debug("(not) updating container %s...", c.PrettyName())
	return nil
}

// ExportResourceData provides resource data to export for the container.
func (a *avx) ExportResourceData(c cache.Container, syntax policy.DataSyntax) []byte {
	return nil
}

func (a *avx) PostStart(cch cache.Container) error {
	a.Debug("post start container...")
	return nil
}

// SetConfig sets the policy backend configuration
func (a *avx) SetConfig(string) error {
	return nil
}

//
// Automatically register us as a policy implementation.
//

// implementation implements policy.Implementation interface which is used to attach policy metadata to a backend creation function (Hm... can't we just use Register()'s parameters to achieve the same effect like `policy.Register(PolicyName, PolicyDescription, createPolicy)`?).
type implementation func(*policy.BackendOptions) policy.Backend

// Name returns the name of this policy implementation.
func (i implementation) Name() string {
	return PolicyName
}

// Description returns the desccription of this policy implementation.
func (i implementation) Description() string {
	return PolicyDescription
}

// CreateFn returns the functions used to instantiate this policy.
func (i implementation) CreateFn() policy.CreateFn {
	return policy.CreateFn(i)
}

func init() {
	policy.Register(implementation(createPolicy))
}
