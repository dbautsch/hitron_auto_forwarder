package main

import (
	"crypto/sha512"
	"encoding/json"
    "encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

const (
	session_name = "hitron_session_co0kie"
)

type ProgramConfiguration struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	HitronUsername string `json:"hitron_username"`
	HitronPassword string `json:"hitron_password"`
	HitronIP       string `json:"hitron_ip"`
    SecretNumber   string `json:"secret_number"`
}

func index_handler(c *gin.Context) {
	session := sessions.Default(c)

	if session.Get("is_logged_in") != "true" {
		c.String(http.StatusForbidden, "Please login first.")
		return
	}

	c.Redirect(http.StatusMovedPermanently, "/control_panel")
}

func control_panel_handler(c *gin.Context) {
	session := sessions.Default(c)

	if session.Get("is_logged_in") != "true" {
		c.String(http.StatusForbidden, "Please login first.")
		return
	}

	render_control_panel(c)
}

func login_handler(c *gin.Context) {
	session := sessions.Default(c)

	if session.Get("is_logged_in") == "true" {
		c.Redirect(http.StatusMovedPermanently, "/control_panel")
		return
	}

	if c.Request.Method == "POST" {
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == "" || password == "" {
			render_login_panel(c, "Error: Both username and password are required")
			return
		}

        configInterface, _ := c.Get("config")
        config := configInterface.(ProgramConfiguration)
        password_hash := sha512.Sum512([]byte(password))
        password_hash_encoded := hex.EncodeToString(password_hash[:])

        if username == config.Username && password_hash_encoded == config.Password {
            session.Set("is_logged_in", "true");
            session.Save()
            c.Redirect(http.StatusMovedPermanently, "/control_panel")
            return
        } else {
			render_login_panel(c, "Error: Incorrect username and/or password.")
			return
        }
	}

	render_login_panel(c, "")
}

func fetch_hitron_data_handler(c *gin.Context) {
	configInterface, _ := c.Get("config")
    config := configInterface.(ProgramConfiguration)
    err := hitron_login()
}

func render_login_panel(c *gin.Context, error_message string) {
	c.HTML(http.StatusOK, "login_panel.html", gin.H{
		"error": error_message,
	})
}

func render_control_panel(c *gin.Context) {
    c.String(http.StatusOK, "Welcome to control panel!")
}

func load_configuration() (ProgramConfiguration, error) {
	file, err := os.Open("configuration/config.json")
	if err != nil {
		return ProgramConfiguration{}, fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return ProgramConfiguration{}, fmt.Errorf("error reading config file: %w", err)
	}

	var config ProgramConfiguration
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return ProgramConfiguration{}, fmt.Errorf("error parsing config JSON: %w", err)
	}

	return config, nil
}

func ConfigMiddleware(config ProgramConfiguration) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("config", config)
		c.Next()
	}
}

func main() {
	config, err := load_configuration()
	if err != nil {
		fmt.Println("Failed to load configuration:", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded configuration: %+v\n", config)

	r := gin.Default()
	r.Use(ConfigMiddleware(config))
	r.Static("/static", "./static/")
	r.LoadHTMLGlob("html/*")
	
    store := cookie.NewStore([]byte("secret_store"))
    store.Options(sessions.Options{
        MaxAge: 3600,  // store session data up to 1 hour
        Path:   "/",
        HttpOnly: true,
    })
	r.Use(sessions.Sessions(session_name, store))

	r.GET("/", index_handler)
	r.GET("/control_panel", control_panel_handler)
	r.GET("/login_handler", login_handler)
	r.POST("/login_handler", login_handler)
    r.GET("fetch_hitron_data", fetch_hitron_data_handler)

	r.Run()
}
