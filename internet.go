package netcon

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	isConnected uint32 = 1
)

var (
	errNotConnected = errors.New("not connected to network")
)

/*
code reference : https://git.zx2c4.com/wireguard-windows/tree/tunnel/winipcfg/winipcfg.go?h=v0.5.3#n37
IpAdapterAddresses struct: https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
*/
func getAdaptersAddresses(family uint32, flags uint32) ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	size := uint32(15000)

	for {
		b = make([]byte, size)
		err := windows.GetAdaptersAddresses(family, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(b)) {
			return nil, err
		}
	}

	result := make([]*windows.IpAdapterAddresses, 0, uintptr(size)/unsafe.Sizeof(windows.IpAdapterAddresses{}))
	for wtiaa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); wtiaa != nil; wtiaa = wtiaa.Next {
		result = append(result, wtiaa)
	}

	return result, nil
}

// IsConnected returns true if there is network connectivity atleast via one network interface
func IsAvailable() (bool, error) {

	ifaces, err := getAdaptersAddresses(0, 0)
	if err != nil {
		return false, err
	}

	for _, addr := range ifaces {
		fmt.Println("adapter name:", windows.UTF16PtrToString(addr.FriendlyName), "status:", addr.OperStatus)
		if addr.OperStatus == isConnected {
			return true, nil
		}
	}

	return false, errNotConnected
}
