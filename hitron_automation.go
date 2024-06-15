package main

import (
	"net/http"
	"net/http/cookiejar"
    "fmt"
    "net/url"
)

func hitron_login(
	hitron_address string,
	username string,
	password string) (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil { 
		return jar, err
	}

	client := &http.Client{
		Jar: jar,
	}
		
	return jar, err
}
