package utils

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// GetTime returns current time in Beijing timezone formatted as "YYYY-MM-DD HH:mm:ss"
func GetTime() string {
	location := time.FixedZone("CST", 8*3600) // UTC+8
	now := time.Now().In(location)
	return now.Format("2006-01-02 15:04:05")
}

// ExtractBetweenTags extracts content between start and end tags
func ExtractBetweenTags(s, startTag, endTag string) string {
	startIndex := strings.Index(s, startTag)
	if startIndex == -1 {
		return ""
	}
	startIndex += len(startTag)
	endIndex := strings.Index(s[startIndex:], endTag)
	if endIndex == -1 {
		return ""
	}
	return s[startIndex : startIndex+endIndex]
}

// RandomMACAddress generates a random MAC address
func RandomMACAddress() string {
	mac := make([]byte, 6)
	rand.Read(mac)
	mac[0] = mac[0] & 0xfe // Clear multicast bit
	
	parts := make([]string, 6)
	for i, b := range mac {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// RandomString generates a random alphanumeric string of given length
func RandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[n.Int64()]
	}
	return string(result)
}

// FixXMLAmpersands replaces unescaped & with &amp; to fix malformed XML
// This mimics the lenient parsing behavior of JSoup used in the Java version
func FixXMLAmpersands(s string) string {
	var result strings.Builder
	result.Grow(len(s))
	
	i := 0
	for i < len(s) {
		if s[i] == '&' {
			// Check if this is already a valid entity reference
			j := i + 1
			foundSemicolon := false
			
			// Look ahead for semicolon (max 10 chars for entity names like &quot; &lt; etc.)
			for j < len(s) && j < i+10 {
				if s[j] == ';' {
					foundSemicolon = true
					break
				}
				if s[j] == ' ' || s[j] == '&' || s[j] == '<' || s[j] == '>' {
					// Not a valid entity reference
					break
				}
				j++
			}
			
			if foundSemicolon {
				// This is already a valid entity reference, keep it as-is
				result.WriteByte('&')
			} else {
				// This is an unescaped &, replace with &amp;
				result.WriteString("&amp;")
			}
			i++
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	
	return result.String()
}

// UnmarshalXML unmarshals XML with automatic fixing of unescaped ampersands
func UnmarshalXML(data []byte, v interface{}) error {
	fixed := FixXMLAmpersands(string(data))
	return xml.Unmarshal([]byte(fixed), v)
}
