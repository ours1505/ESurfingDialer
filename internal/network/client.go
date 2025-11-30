package network

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Rsplwe/ESurfingDialer/internal/constants"
	"github.com/Rsplwe/ESurfingDialer/internal/states"
)

// NetResult represents a network operation result
type NetResult struct {
	Data  []byte
	Error error
}

// CreateHTTPClient creates an HTTP client with custom redirect handling
// If states.Interface is set, the client will bind to that network interface
func CreateHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			
			// If interface is specified, bind to it
			if states.Interface != "" {
				localAddr, err := getInterfaceAddr(states.Interface)
				if err != nil {
					fmt.Printf("Warning: Failed to get interface %s address: %v\n", states.Interface, err)
				} else {
					dialer.LocalAddr = &net.TCPAddr{IP: localAddr}
				}
			}
			
			return dialer.DialContext(ctx, network, addr)
		},
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects automatically, we'll handle them manually
			return http.ErrUseLastResponse
		},
	}
}

// getInterfaceAddr returns the first IPv4 address of the specified network interface
func getInterfaceAddr(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %v", ifaceName, err)
	}
	
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for %s: %v", ifaceName, err)
	}
	
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		
		// Return first IPv4 address
		if ip != nil && ip.To4() != nil {
			return ip, nil
		}
	}
	
	return nil, fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}

// Post sends a POST request with encrypted data
func Post(client *http.Client, url string, data string, extraHeaders map[string]string) *NetResult {
	body := bytes.NewBufferString(data)
	
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return &NetResult{Error: err}
	}

	// Set headers
	req.Header.Set("User-Agent", constants.UserAgent)
	req.Header.Set("Accept", constants.RequestAccept)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("CDC-Checksum", MD5Hash(data))
	req.Header.Set("Client-ID", states.ClientID)
	req.Header.Set("Algo-ID", states.AlgoID)

	// Add extra headers
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	// Add CDC headers if available
	if states.SchoolID != "" {
		req.Header.Set("CDC-SchoolId", states.SchoolID)
	}
	if states.Domain != "" {
		req.Header.Set("CDC-Domain", states.Domain)
	}
	if states.Area != "" {
		req.Header.Set("CDC-Area", states.Area)
	}

	resp, err := client.Do(req)
	if err != nil {
		return &NetResult{Error: err}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &NetResult{Error: err}
	}

	return &NetResult{Data: respData, Error: nil}
}

// MD5Hash calculates MD5 hash of a string
func MD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// HandleRedirects manually handles HTTP redirects and extracts headers
func HandleRedirects(client *http.Client, initialURL string) (*http.Response, error) {
	maxRedirects := 5
	currentURL := initialURL
	
	for i := 0; i < maxRedirects; i++ {
		req, err := http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return nil, err
		}
		
		req.Header.Set("User-Agent", constants.UserAgent)
		req.Header.Set("Accept", constants.RequestAccept)
		req.Header.Set("Client-ID", states.ClientID)
		
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		
		// Check for redirect headers
		if area := resp.Header.Get("area"); area != "" {
			states.Area = area
			fmt.Printf("Add Header -> CDC-Area: %s\n", states.Area)
		}
		if schoolID := resp.Header.Get("schoolid"); schoolID != "" {
			states.SchoolID = schoolID
			fmt.Printf("Add Header -> CDC-SchoolId: %s\n", states.SchoolID)
		}
		if domain := resp.Header.Get("domain"); domain != "" {
			states.Domain = domain
			fmt.Printf("Add Header -> CDC-Domain: %s\n", states.Domain)
		}
		
		// If not a redirect, return the response
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}
		
		// Get redirect location
		location := resp.Header.Get("Location")
		if location == "" {
			return resp, nil
		}
		
		resp.Body.Close()
		currentURL = location
		fmt.Printf("Redirect #%d to: %s\n", i+1, currentURL)
	}
	
	return nil, fmt.Errorf("too many redirects")
}
