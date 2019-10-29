package avx

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/intel/cri-resource-manager/pkg/cgroupid"
	bpf "github.com/iovisor/gobpf/elf"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	lastCPUDesc = prometheus.NewDesc(
		"last_cpu_avx_task_switches",
		"Number of task switches on the CPU where AVX512 instructions were used.",
		[]string{
			"cpu_id",
		}, nil,
	)

	avxSwitchCountDesc = prometheus.NewDesc(
		"avx_switch_count_per_cgroup",
		"Number of task switches where AVX512 instructions were used in a particular cgroup.",
		[]string{
			"cgroup",
		}, nil,
	)

	allSwitchCountDesc = prometheus.NewDesc(
		"all_switch_count_per_cgroup",
		"Total number of task switches in a particular cgroup.",
		[]string{
			"cgroup",
		}, nil,
	)
)

type collector struct {
	root                     string
	elfFilepath              string
	bpfModule                *bpf.Module
	avxContextSwitchCounters *bpf.Map
	allContextSwitchCounters *bpf.Map
	lastCPUCounters          *bpf.Map
}

// NewCollector creates new Prometheus collector for AVX metrics
func NewCollector(root, elfFilepath string) (prometheus.Collector, error) {
	bpfModule := bpf.NewModule(elfFilepath)

	sectionParams := make(map[string]bpf.SectionParams)
	if err := bpfModule.Load(sectionParams); err != nil {
		return nil, errors.Wrap(err, "unable to load eBPF ELF file")
	}

	allSwitchCounters := bpfModule.Map("all_context_switch_count")
	if allSwitchCounters == nil {
		return nil, errors.New("map all_context_switch_count not found")
	}

	avxSwitchCounters := bpfModule.Map("avx_context_switch_count")
	if avxSwitchCounters == nil {
		return nil, errors.New("map avx_context_switch_count not found")
	}

	lastCPUCounters := bpfModule.Map("cpu")
	if lastCPUCounters == nil {
		return nil, errors.New("map cpu not found")
	}

	if err := bpfModule.EnableTracepoint("tracepoint/sched/sched_switch"); err != nil {
		return nil, errors.Wrap(err, "couldn't enable tracepoint/sched/sched_switch")
	}

	if err := bpfModule.EnableTracepoint("tracepoint/x86_fpu/x86_fpu_regs_deactivated"); err != nil {
		return nil, errors.Wrap(err, "couldn't enable tracepoint/x86_fpu/x86_fpu_regs_deactivated")
	}

	return &collector{
		root:                     root,
		bpfModule:                bpfModule,
		avxContextSwitchCounters: avxSwitchCounters,
		allContextSwitchCounters: allSwitchCounters,
		lastCPUCounters:          lastCPUCounters,
	}, nil
}

// Describe implements prometheus.Collector interface
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect implements prometheus.Collector interface
func (c collector) Collect(ch chan<- prometheus.Metric) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.collectLastCPUStats(ch)
	}()

	cg := cgroupid.NewCgroupID(c.root)
	cgroupids, counters, err := c.moveAllElements(c.avxContextSwitchCounters, unsafe.Sizeof(uint64(0)), unsafe.Sizeof(uint32(0)))
	if err != nil {
		fmt.Printf("unable to move elements of avx_context_switch_count: %+v\n", err)
	}

	for idx, cgroupid := range cgroupids {
		wg.Add(1)
		go func(idx_ int, cgroupid_ []byte) {
			var allCount uint32

			defer wg.Done()

			path, err := cg.Find(binary.LittleEndian.Uint64(cgroupid_[0:]))
			if err != nil {
				fmt.Println(err)
				return
			}

			if err := c.bpfModule.LookupElement(c.allContextSwitchCounters, unsafe.Pointer(&cgroupid_[0]), unsafe.Pointer(&allCount)); err != nil {
				fmt.Printf("unable to find avx switch count: %+v\n", err)
				return
			}

			ch <- prometheus.MustNewConstMetric(
				avxSwitchCountDesc,
				prometheus.GaugeValue,
				float64(binary.LittleEndian.Uint32(counters[idx_][0:])),
				path)
			ch <- prometheus.MustNewConstMetric(
				allSwitchCountDesc,
				prometheus.GaugeValue,
				float64(allCount),
				path)
		}(idx, cgroupid)
	}

	_, _, err = c.moveAllElements(c.allContextSwitchCounters, unsafe.Sizeof(uint64(0)), unsafe.Sizeof(uint32(0)))
	if err != nil {
		fmt.Printf("unable to delete elements of all_context_switch_count: %+v\n", err)
	}

	// We need to wait so that the response channel doesn't get closed.
	wg.Wait()
}

func (c *collector) moveAllElements(table *bpf.Map, keySize, valueSize uintptr) ([][]byte, [][]byte, error) {
	var keys [][]byte
	var values [][]byte

	zero := make([]byte, keySize)
	nextKey := make([]byte, keySize)
	value := make([]byte, valueSize)

	for {
		ok, err := c.bpfModule.LookupNextElement(table, unsafe.Pointer(&zero[0]), unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value[0]))
		if err != nil {
			return nil, nil, errors.Wrap(err, "unable to look up")
		}

		if !ok {
			break
		}

		keyClone := append(nextKey[:0:0], nextKey...)
		keys = append(keys, keyClone)

		valueClone := append(value[:0:0], value...)
		values = append(values, valueClone)

		if err := c.bpfModule.DeleteElement(table, unsafe.Pointer(&nextKey[0])); err != nil {
			return nil, nil, errors.Wrap(err, "unable to delete")
		}
	}

	return keys, values, nil
}

func (c collector) collectLastCPUStats(ch chan<- prometheus.Metric) {
	// NB: (* struct fpu)->last_cpu is of type `unsigned int` which translates to Go's uint32, not uint (4 bytes size in IA)
	lastCPUs, counters, err := c.moveAllElements(c.lastCPUCounters, unsafe.Sizeof(uint32(0)), unsafe.Sizeof(uint32(0)))
	if err != nil {
		fmt.Printf("unable to move elements of cpu map: %+v\n", err)
		return
	}

	for idx, lastCPU := range lastCPUs {
		ch <- prometheus.MustNewConstMetric(
			lastCPUDesc,
			prometheus.GaugeValue,
			float64(binary.LittleEndian.Uint32(counters[idx])),
			fmt.Sprintf("CPU%d", binary.LittleEndian.Uint32(lastCPU)))
	}
}
