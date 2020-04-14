// +build freebsd

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package mount

import (
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var (
	ErrNotImplementedOnFreeBSD = errors.New("not implemented under FreeBSD")
)

// Mount to the provided target path.
//
// Only support ZFS
func (m *Mount) Mount(target string) error {
	if m.Type != "zfs" {
		return ErrNotImplementedOnFreeBSD
	}
	return mount(m.Source, target, m.Type, 0, nil)
}

// Unmount the provided mount path with the flags
func Unmount(mount string, flags int) error {
	if err := unmount(mount, flags); err != nil && err != unix.EINVAL {
		return err
	}
	return nil
}

// UnmountAll repeatedly unmounts the given mount point until there
// are no mounts remaining (EINVAL is returned by mount), which is
// useful for undoing a stack of mounts on the same mount point.
// UnmountAll all is noop when the first argument is an empty string.
// This is done when the containerd client did not specify any rootfs
// mounts (e.g. because the rootfs is managed outside containerd)
// UnmountAll is noop when the mount path does not exist.
func UnmountAll(mount string, flags int) error {
	if mount == "" {
		return nil
	}
	if _, err := os.Stat(mount); os.IsNotExist(err) {
		return nil
	}

	for {
		if err := unmount(mount, flags); err != nil {
			// EINVAL is returned if the target is not a
			// mount point, indicating that we are
			// done. It can also indicate a few other
			// things (such as invalid flags) which we
			// unfortunately end up squelching here too.
			if err == unix.EINVAL {
				return nil
			}
			return err
		}
	}
}

// Implement mount on FreeBSD by nmount(2)
func mount(source string, target string, fstype string, flags uintptr, _ *byte) (err error) {
	iov := [6]syscall.Iovec{}
	err = buildiov(&iov[0], "fstype")
	if err != nil {
		return
	}
	err = buildiov(&iov[1], fstype)
	if err != nil {
		return
	}
	err = buildiov(&iov[2], "fspath")
	if err != nil {
		return
	}
	err = buildiov(&iov[3], target)
	if err != nil {
		return
	}
	err = buildiov(&iov[4], "from")
	if err != nil {
		return
	}
	err = buildiov(&iov[5], source)
	if err != nil {
		return
	}
	_, _, errno := syscall.Syscall(unix.SYS_NMOUNT, uintptr(unsafe.Pointer(&iov[0])), uintptr(6), flags)
	if errno != 0 {
		err = errno
	}
	return
}

func buildiov(iov *syscall.Iovec, field string) error {
	ptr, err := syscall.BytePtrFromString(field)
	if err != nil {
		return err
	}
	iov.Base = ptr
	iov.SetLen(len(field) + 1)
	return nil
}

func unmount(target string, flags int) error {
	for i := 0; i < 50; i++ {
		if err := unix.Unmount(target, flags); err != nil {
			switch err {
			case unix.EBUSY:
				time.Sleep(50 * time.Millisecond)
				continue
			default:
				return err
			}
		}
		return nil
	}
	return errors.Wrapf(unix.EBUSY, "failed to unmount target %s", target)
}
