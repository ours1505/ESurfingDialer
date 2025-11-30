package network

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Rsplwe/ESurfingDialer/internal/constants"
	"github.com/Rsplwe/ESurfingDialer/internal/models"
	"github.com/Rsplwe/ESurfingDialer/internal/states"
	"github.com/Rsplwe/ESurfingDialer/internal/utils"
)

// PortalConfig represents the XML configuration structure
type PortalConfig struct {
	XMLName   xml.Name `xml:"config"`
	AuthURL   string   `xml:"auth-url"`
	TicketURL string   `xml:"ticket-url"`
	FuncCfg   struct {
		Items []FuncCfgItem `xml:",any"`
	} `xml:"funcfg"`
}

// FuncCfgItem represents a function configuration item
type FuncCfgItem struct {
	XMLName xml.Name
	Enable  string `xml:"enable,attr"`
	URL     string `xml:"url,attr"`
}

// ConnectivityStatus represents network connectivity states
type ConnectivityStatus int

const (
	Success ConnectivityStatus = iota
	RequireAuthorization
	RequestError
)

// DetectConfig detects network configuration and authorization requirements
func DetectConfig() ConnectivityStatus {
	client := CreateHTTPClient()
	
	resp, err := HandleRedirects(client, constants.CaptiveURL)
	if err != nil {
		fmt.Printf("Request Error: %v\n", err)
		return RequestError
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		fmt.Printf("Request Code: %d\n", resp.StatusCode)
		return RequestError
	}
	
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return RequestError
	}
	
	portalConfig := utils.ExtractBetweenTags(string(content), constants.PortalStartTag, constants.PortalEndTag)
	if portalConfig == "" {
		return Success
	}
	
	// Debug: Print the extracted portal config
	fmt.Printf("Portal Config extracted: %s\n", portalConfig)
	
	// Parse XML configuration (using lenient parser that handles unescaped ampersands)
	var config PortalConfig
	err = utils.UnmarshalXML([]byte(portalConfig), &config)
	if err != nil {
		fmt.Printf("Error parsing XML: %v\n", err)
		fmt.Printf("XML content: %s\n", portalConfig)
		return RequestError
	}
	
	states.AuthURL = strings.TrimSpace(config.AuthURL)
	states.TicketURL = strings.TrimSpace(config.TicketURL)
	
	// Decode HTML entities in URLs (e.g., &amp; to &)
	states.AuthURL = strings.ReplaceAll(states.AuthURL, "&amp;", "&")
	states.TicketURL = strings.ReplaceAll(states.TicketURL, "&amp;", "&")
	
	fmt.Printf("Parsed auth-url: %s\n", states.AuthURL)
	fmt.Printf("Parsed ticket-url: %s\n", states.TicketURL)
	
	// Parse extra function URLs
	for _, item := range config.FuncCfg.Items {
		if item.Enable == "1" && item.URL != "" {
			states.ExtraCfgURL[item.XMLName.Local] = item.URL
			fmt.Printf("Added extra config: %s -> %s\n", item.XMLName.Local, item.URL)
		}
	}
	
	if states.AuthURL == "" || states.TicketURL == "" {
		fmt.Printf("Missing auth-url or ticket-url. AuthURL='%s', TicketURL='%s'\n", states.AuthURL, states.TicketURL)
		return RequestError
	}
	
	// Parse URL parameters
	ticketURL, err := url.Parse(states.TicketURL)
	if err != nil {
		fmt.Printf("Error parsing ticket URL: %v\n", err)
		return RequestError
	}
	
	params := ticketURL.Query()
	states.UserIP = params.Get("wlanuserip")
	states.ACIP = params.Get("wlanacip")
	
	if states.UserIP == "" || states.ACIP == "" {
		fmt.Println("Missing userIp or acIp")
		return RequestError
	}
	
	return RequireAuthorization
}

// CheckVerifyCodeStatus checks if SMS verification is required
func CheckVerifyCodeStatus(username string) bool {
	return requestVerifyCode(username, "QueryVerificateCodeStatus", "11062000")
}

// GetVerifyCode requests SMS verification code
func GetVerifyCode(username string) bool {
	return requestVerifyCode(username, "QueryAuthCode", "0")
}

func requestVerifyCode(username, reqType, successCode string) bool {
	url, exists := states.ExtraCfgURL[reqType]
	if !exists || url == "" {
		return false
	}
	
	timestamp := fmt.Sprintf("%d", currentTimeMillis())
	authenticator := md5.Sum([]byte(states.SchoolID + timestamp + constants.AuthKey))
	
	reqData := models.RequireVerificate{
		SchoolID:      states.SchoolID,
		Username:      username,
		Timestamp:     timestamp,
		Authenticator: strings.ToUpper(hex.EncodeToString(authenticator[:])),
	}
	
	jsonData, err := json.Marshal(reqData)
	if err != nil {
		return false
	}
	
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return false
	}
	
	req.Header.Set("User-Agent", constants.UserAgent)
	req.Header.Set("Accept", "okhttp/3.4.1")
	req.Header.Set("Content-Type", "application/json")
	
	client := CreateHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error requesting verify code: %v\n", err)
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return false
	}
	
	var result models.ResponseRequireVerificate
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("Error decoding response: %v\n", err)
		return false
	}
	
	return result.ResCode == successCode
}

func currentTimeMillis() int64 {
	return timeNow().UnixNano() / 1e6
}

// For testing purposes
var timeNow = func() interface{ UnixNano() int64 } {
	return timeProvider{}
}

type timeProvider struct{}

func (timeProvider) UnixNano() int64 {
	return time.Now().UnixNano()
}
