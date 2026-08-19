package utils

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

var (
	modkernel32             = syscall.NewLazyDLL("kernel32.dll")
	procMultiByteToWideChar = modkernel32.NewProc("MultiByteToWideChar")
)

const CP_ACP = 0

var systemRoot string

func init() {
	systemRoot = os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
}

func resolveCmd(name string) string {
	system32 := filepath.Join(systemRoot, "System32")
	switch strings.ToLower(name) {
	case "wmic":
		return filepath.Join(system32, "wbem", "wmic.exe")
	case "ping", "arp", "route", "netstat", "hostname", "nbtstat":
		return filepath.Join(system32, name+".exe")
	case "net", "whoami", "nltest", "gpresult", "query", "schtasks", "netsh":
		return filepath.Join(system32, name+".exe")
	case "ipconfig":
		return filepath.Join(system32, "ipconfig.exe")
	default:
		return name
	}
}

func decodeACP(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	isValidUTF8 := true
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			isValidUTF8 = false
			break
		}
		i += size
	}
	if isValidUTF8 {
		return string(data)
	}

	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16LE(data[2:])
	}

	return decodeGBK(data)
}

func decodeGBK(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	ret, _, _ := procMultiByteToWideChar.Call(
		CP_ACP,
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
		0,
	)
	if ret == 0 {
		return string(data)
	}

	buf := make([]uint16, ret)
	ret, _, _ = procMultiByteToWideChar.Call(
		CP_ACP,
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return string(data)
	}

	return string(utf16.Decode(buf[:ret]))
}

func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	return string(utf16.Decode(u16))
}

func RunCmd(name string, args ...string) (string, error) {
	resolved := resolveCmd(name)
	cmd := exec.Command(resolved, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
	output, err := cmd.CombinedOutput()
	decoded := strings.TrimSpace(decodeACP(output))
	if err != nil {
		return decoded, err
	}
	return decoded, nil
}

func RunCmdWithTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	resolved := resolveCmd(name)
	cmd := exec.Command(resolved, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return "", err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		cmd.Process.Kill()
		return strings.TrimSpace(decodeACP(buf.Bytes())), nil
	case err := <-done:
		return strings.TrimSpace(decodeACP(buf.Bytes())), err
	}
}

func RunWmic(query string) (string, error) {
	args := strings.Fields(query)
	return RunCmd("wmic", args...)
}