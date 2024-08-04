package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Define a map of valid usernames and passwords - in production it will be checked against db
var validUsers = map[string]string{
	"admin": "password123",
	"user1": "user1pass",
	"guest": "guestpass",
}

// BasicAuth middleware
func BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if Authorization header is present
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// No Authorization header present, request authentication
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Authorization required")
			return
		}

		// Extract username and password from Authorization header
		auth := strings.Split(authHeader, " ")
		if len(auth) != 2 || auth[0] != "Basic" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Invalid Authorization header")
			return
		}

		// Decode Base64 username:password
		payload, err := base64.StdEncoding.DecodeString(auth[1])
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Invalid base64 encoding")
			return
		}

		// Split payload into username and password
		pair := strings.Split(string(payload), ":")
		if len(pair) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Invalid payload")
			return
		}
		username := pair[0]
		password := pair[1]

		// Check if username and password are valid
		expectedPassword, ok := validUsers[username]
		if !ok || password != expectedPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Invalid credentials")
			return
		}

		// If credentials are valid, call the next handler
		next.ServeHTTP(w, r)
	}
}

// Handler for protected endpoint
func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is a protected endpoint")
}

func main() {
	// Register the BasicAuth middleware with the ProtectedEndpoint handler
	http.HandleFunc("/protected", BasicAuth(ProtectedEndpoint))

	// Start the server
	fmt.Println("Server running on http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
