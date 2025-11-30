package states

import (
	"strings"

	"github.com/Rsplwe/ESurfingDialer/internal/utils"
	"github.com/google/uuid"
)

var (
	ClientID    string
	AlgoID      string
	MacAddress  string
	Ticket      string
	UserIP      string
	ACIP        string
	IsRunning   bool = true
	SchoolID    string
	Domain      string
	Area        string
	TicketURL   string
	AuthURL     string
	ExtraCfgURL = make(map[string]string)
	IsLogged    bool
	Interface   string // Network interface name for binding (e.g., eth0, wan)
)

// RefreshStates refreshes the client state with new random values
func RefreshStates() {
	ClientID = strings.ToLower(uuid.New().String())
	AlgoID = "00000000-0000-0000-0000-000000000000"
	if MacAddress == "" {
		MacAddress = utils.RandomMACAddress()
	}
}
