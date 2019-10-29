package cgroupid

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type CgroupID struct {
	root  string
	cache map[uint64]string
}

func NewCgroupID(root string) *CgroupID {
	return &CgroupID{
		root:  root,
		cache: make(map[uint64]string),
	}
}

func getID(path string) uint64 {
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0
	}

	return binary.LittleEndian.Uint64(h.Bytes())
}

func (cgid *CgroupID) List() error {
	return filepath.Walk(cgid.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("WalkFunc called with an error (path %q: %v\n)", path, err)
			return err
		}

		if info.IsDir() {
			fmt.Printf("%v - %s\n", getID(path), path)
		}
		return nil
	})
}

func (cgid *CgroupID) Find(id uint64) (string, error) {
	found := false
	var p string

	if path, ok := cgid.cache[id]; ok {
		return path, nil
	}

	err := filepath.Walk(cgid.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("WalkFunc called with an error (path %q: %v\n)", path, err)
			return err
		}

		if found {
			return filepath.SkipDir
		}

		if info.IsDir() && id == getID(path) {
			found = true
			p = path
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("cgroupid %v not found", id)
	} else {
		cgid.cache[id] = p
		return p, nil
	}
}
