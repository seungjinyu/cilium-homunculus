package socketlb

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var attachTypes = map[string]ebpf.AttachType{
	Connect4:     ebpf.AttachCGroupInet4Connect,
	SendMsg4:     ebpf.AttachCGroupUDP4Sendmsg,
	RecvMsg4:     ebpf.AttachCGroupUDP4Recvmsg,
	GetPeerName4: ebpf.AttachCgroupInet4GetPeername,
	PostBind4:    ebpf.AttachCGroupInet4PostBind,
	PreBind4:     ebpf.AttachCGroupInet4Bind,
	Connect6:     ebpf.AttachCGroupInet6Connect,
	SendMsg6:     ebpf.AttachCGroupUDP6Sendmsg,
	RecvMsg6:     ebpf.AttachCGroupUDP6Recvmsg,
	GetPeerName6: ebpf.AttachCgroupInet6GetPeername,
	PostBind6:    ebpf.AttachCGroupInet6PostBind,
	PreBind6:     ebpf.AttachCGroupInet6Bind,
}

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

		log.Printf("Unpinned defunct link %s for program %s", pin, name)
	case errors.Is(err, os.ErrNotExist):
		log.Printf("No existing link found at %s for program %s", pin, name)

	default:
		return fmt.Errorf("updating link %s for program %s: %w", pin, name, err)

	}

	cg, err := os.Open(cgroupRoot)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", cgroupRoot, err)
	}
	defer cg.Close()

	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cg.Fd()),
		Program: prog,
		Attach:  attachTypes[name],
	})
	if err == nil {
		defer func() {
			// The program was successfully attached using bpf_link. Closing a link
			// does not detach the program if the link is pinned.
			if err := l.Close(); err != nil {
				log.Printf("Failed to close bpf_link for program %s", name)
			}
		}()

		if err := l.Pin(pin); err != nil {
			return fmt.Errorf("pin link at %s for program %s : %w", pin, name, err)
		}

		// Successfully created and pinned bpf_link.
		log.Printf("Program %s attached using bpf_link", name)

		return nil
	}

	// Kernels before 5.7 don't support bpf_link. In that case link.AttachRawLink
	// returns ErrNotSupported.
	//
	// If the kernel supports bpf_link, but an older version of Cilium attached a
	// cgroup program without flags (old init.sh behaviour), link.AttachRawLink
	// will return EPERM because bpf_link implicitly uses the multi flag.
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, link.ErrNotSupported) {
		// Unrecoverable error from AttachRawLink.
		return fmt.Errorf("attach program %s using bpf_link: %w", name, err)
	}

	log.Printf("Performing PROG_ATTACH for program %s", name)

	// Call PROG_ATTACH without flags to attach the program if bpf_link is not
	// available or a previous PROG_ATTACH without flags has to be seamlessly
	// replaced.
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cg.Fd()),
		Program: prog,
		Attach:  attachTypes[name],
	}); err != nil {
		return fmt.Errorf("PROG_ATTACH for program %s: %w", name, err)
	}

	// Nothing left to do, the cgroup now holds a reference to the prog
	// so we don't need to hold a reference in the agent/bpffs to ensure
	// the program stays active.
	log.Printf("Program %s was attached using PROG_ATTACH", name)
	return nil

}
