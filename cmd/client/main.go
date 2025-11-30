package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Rsplwe/ESurfingDialer/internal/client"
	"github.com/Rsplwe/ESurfingDialer/internal/models"
	"github.com/Rsplwe/ESurfingDialer/internal/session"
	"github.com/Rsplwe/ESurfingDialer/internal/states"
)

func main() {
	// Parse command line arguments
	user := flag.String("u", "", "Login User (Phone Number or Other)")
	flag.StringVar(user, "user", "", "Login User (Phone Number or Other)")
	
	password := flag.String("p", "", "Login User Password")
	flag.StringVar(password, "password", "", "Login User Password")
	
	smsCode := flag.String("s", "", "Pre-enter verification code")
	flag.StringVar(smsCode, "sms", "", "Pre-enter verification code")
	
	macAddr := flag.String("m", "", "MAC address (e.g., aa:bb:cc:dd:ee:ff)")
	flag.StringVar(macAddr, "mac", "", "MAC address (e.g., aa:bb:cc:dd:ee:ff)")
	
	flag.Parse()

	if *user == "" || *password == "" {
		fmt.Println("Error: user and password are required")
		flag.Usage()
		os.Exit(1)
	}

	options := &models.Options{
		LoginUser:     *user,
		LoginPassword: *password,
		SmsCode:       *smsCode,
	}

	c := client.New(options)

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		states.IsRunning = false
		if states.IsLogged {
			c.Term()
		}
		if session.IsInitialized() {
			session.Free()
		}
		os.Exit(0)
	}()

	// Refresh states and run client
	states.RefreshStates()
	if *macAddr != "" {
		states.MacAddress = *macAddr
	}
	c.Run()
}
