package models

// RequireVerificate represents the verification request
type RequireVerificate struct {
	SchoolID      string `json:"schoolid"`
	Username      string `json:"username"`
	Timestamp     string `json:"timestamp"`
	Authenticator string `json:"authenticator"`
}

// ResponseRequireVerificate represents the verification response
type ResponseRequireVerificate struct {
	Phone   string `json:"phone"`
	ResInfo string `json:"resinfo"`
	ResCode string `json:"rescode"`
}
