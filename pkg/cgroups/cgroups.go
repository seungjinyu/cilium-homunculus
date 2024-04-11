package cgroups

import (
	"log"
	"sync"

	"github.com/seungjinyu/cilium-homunculus/pkg/defaults"
)

var (
	cgroupRoot = defaults.DefaultCgroupRoot

	cgrpMountOnce sync.Once
)

func setCgroupRoot(path string) {
	cgroupRoot = path
}

func GetCgroupRoot() string {
	return cgroupRoot
}

func CheckOrMountCgrpFS(mapRoot string) {
	cgrpMountOnce.Do(func() {

		if mapRoot == "" {
			mapRoot = cgroupRoot
		}

		if err := cgrpCheckOrMountLocation(mapRoot); err != nil {
			// log.WithError(err).Warn
			log.Println("Warning")

		} else {
			// log.Infof
			log.Printf("Mounted cgroupv2 filesystem at %s", mapRoot)
		}

	})
}
