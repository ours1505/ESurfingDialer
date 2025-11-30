package client

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Rsplwe/ESurfingDialer/internal/constants"
	"github.com/Rsplwe/ESurfingDialer/internal/models"
	"github.com/Rsplwe/ESurfingDialer/internal/network"
	"github.com/Rsplwe/ESurfingDialer/internal/session"
	"github.com/Rsplwe/ESurfingDialer/internal/states"
	"github.com/Rsplwe/ESurfingDialer/internal/utils"
)

// XML response structures
type TicketResponse struct {
	XMLName xml.Name `xml:"response"`
	Ticket  string   `xml:"ticket"`
}

type LoginResponse struct {
	XMLName   xml.Name `xml:"response"`
	KeepURL   string   `xml:"keep-url"`
	TermURL   string   `xml:"term-url"`
	KeepRetry string   `xml:"keep-retry"`
}

type HeartbeatResponse struct {
	XMLName  xml.Name `xml:"response"`
	Interval string   `xml:"interval"`
}

// Client handles the authentication and keep-alive logic
type Client struct {
	options   *models.Options
	keepURL   string
	termURL   string
	keepRetry string
	tick      int64
	httpClient *http.Client
}

// New creates a new Client instance
func New(options *models.Options) *Client {
	return &Client{
		options:    options,
		httpClient: network.CreateHTTPClient(),
	}
}

// Run starts the main client loop
func (c *Client) Run() {
	for states.IsRunning {
		networkStatus := network.DetectConfig()
		
		switch networkStatus {
		case network.Success:
			if session.IsInitialized() && states.IsLogged {
				if (time.Now().UnixMilli() - c.tick) >= (parseRetry(c.keepRetry) * 1000) {
					fmt.Println("Send Keep Packet")
					c.heartbeat(states.Ticket)
					fmt.Printf("Next Retry: %s\n", c.keepRetry)
					c.tick = time.Now().UnixMilli()
				}
			} else {
				fmt.Println("The network has been connected.")
			}
			time.Sleep(1 * time.Second)
			
		case network.RequireAuthorization:
			states.IsLogged = false
			c.authorization()
			
		case network.RequestError:
			fmt.Println("Request Error")
			time.Sleep(5 * time.Second)
		}
	}
}

func (c *Client) authorization() {
	code := c.options.SmsCode
	if code == "" {
		code = c.checkSMSVerify()
	}
	fmt.Printf("SMS Code is: %s\n", code)
	
	states.RefreshStates()
	c.initSession()
	
	if !session.IsInitialized() {
		fmt.Println("Unable to find algorithm implementation, please restart the application or try version 1.8.0 or below.")
		fmt.Println("Release: https://github.com/Rsplwe/ESurfingDialer/releases")
		states.IsRunning = false
		return
	}
	
	fmt.Printf("Client IP: %s\n", states.UserIP)
	fmt.Printf("AC IP: %s\n", states.ACIP)
	
	states.Ticket = c.getTicket()
	fmt.Printf("Ticket: %s\n", states.Ticket)
	
	c.login(code)
	if c.keepURL == "" {
		fmt.Println("KeepUrl is empty.")
		session.Free()
		states.IsRunning = false
		return
	}
	
	c.tick = time.Now().UnixMilli()
	states.IsLogged = true
	fmt.Println("The login has been authorized.")
}

func (c *Client) checkSMSVerify() string {
	if network.CheckVerifyCodeStatus(c.options.LoginUser) && network.GetVerifyCode(c.options.LoginUser) {
		fmt.Println("This login requires a SMS verification code.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Input Code: ")
			input, _ := reader.ReadString('\n')
			code := strings.TrimSpace(input)
			if code != "" {
				return code
			}
		}
	}
	return ""
}

func (c *Client) initSession() {
	result := network.Post(c.httpClient, states.TicketURL, states.AlgoID, nil)
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return
	}
	session.Initialize(result.Data)
}

func (c *Client) getTicket() string {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
    <gwip>%s</gwip>
</request>`,
		constants.UserAgent,
		states.ClientID,
		utils.GetTime(),
		constants.HostName,
		states.UserIP,
		states.MacAddress,
		constants.HostName,
		states.ACIP,
	)
	
	result := network.Post(c.httpClient, states.TicketURL, session.Encrypt(payload), nil)
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return ""
	}
	
	data := session.Decrypt(string(result.Data))
	
	var resp TicketResponse
	err := utils.UnmarshalXML([]byte(data), &resp)
	if err != nil {
		fmt.Printf("Error parsing ticket XML: %v\n", err)
		fmt.Printf("XML data: %s\n", data)
		return ""
	}
	
	return strings.TrimSpace(resp.Ticket)
}

func (c *Client) login(code string) {
	verify := ""
	if code != "" {
		verify = fmt.Sprintf("<verify>%s</verify>", code)
	}
	
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <ticket>%s</ticket>
    <local-time>%s</local-time>
    <userid>%s</userid>
    <passwd>%s</passwd>
    %s
</request>`,
		constants.UserAgent,
		states.ClientID,
		states.Ticket,
		utils.GetTime(),
		c.options.LoginUser,
		c.options.LoginPassword,
		verify,
	)
	
	result := network.Post(c.httpClient, states.AuthURL, session.Encrypt(payload), nil)
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return
	}
	
	data := session.Decrypt(string(result.Data))
	
	var resp LoginResponse
	err := utils.UnmarshalXML([]byte(data), &resp)
	if err != nil {
		fmt.Printf("Error parsing login XML: %v\n", err)
		fmt.Printf("XML data: %s\n", data)
		return
	}
	
	c.keepURL = strings.TrimSpace(resp.KeepURL)
	c.termURL = strings.TrimSpace(resp.TermURL)
	c.keepRetry = strings.TrimSpace(resp.KeepRetry)
	
	fmt.Printf("Keep Url: %s\n", c.keepURL)
	fmt.Printf("Term Url: %s\n", c.termURL)
	fmt.Printf("Keep Retry: %s\n", c.keepRetry)
}

func (c *Client) heartbeat(ticket string) {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>`,
		constants.UserAgent,
		states.ClientID,
		utils.GetTime(),
		constants.HostName,
		states.UserIP,
		ticket,
		states.MacAddress,
		constants.HostName,
	)
	
	result := network.Post(c.httpClient, c.keepURL, session.Encrypt(payload), nil)
	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return
	}
	
	data := session.Decrypt(string(result.Data))
	
	var resp HeartbeatResponse
	err := utils.UnmarshalXML([]byte(data), &resp)
	if err != nil {
		fmt.Printf("Error parsing heartbeat XML: %v\n", err)
		fmt.Printf("XML data: %s\n", data)
		return
	}
	
	if resp.Interval != "" {
		c.keepRetry = strings.TrimSpace(resp.Interval)
	}
}

// Term terminates the session
func (c *Client) Term() {
	payload := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>`,
		constants.UserAgent,
		states.ClientID,
		utils.GetTime(),
		constants.HostName,
		states.UserIP,
		states.Ticket,
		states.MacAddress,
		constants.HostName,
	)
	
	network.Post(c.httpClient, c.termURL, session.Encrypt(payload), nil)
}

func parseRetry(retry string) int64 {
	var result int64
	fmt.Sscanf(retry, "%d", &result)
	return result
}
