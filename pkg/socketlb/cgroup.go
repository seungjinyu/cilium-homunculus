package socketlb

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func attachCgroup(spec *ebpf.Collection, name, cgroupRoot, pinPath string) error {
	prog := spec.Programs[name]
	if prog == nil {
		return fmt.Errorf("program %s not found in ELF", name)
	}

	pin := filepath.Join(pinPath, name)
	err := bpf.UpdateLink(pin, prog)

	switch {
	case err == nil:
		log.Printf("Updated link %s for program %s", pin, name)

		return nil

	case errors.Is(err, unix.ENOLINK):
		if err := os.Remove(pin); err != nil {
			return fmt.Errorf("unpinning defunct link %s: %w", pin, err)
		}

		log.Printf("Unpinned defunct link %s for program %s", pin, name)\
	}
	return nil

}
