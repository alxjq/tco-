package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Global database connection
var db *sql.DB

// Stores currently connected users (username -> Client struct)
var clients = make(map[string]*Client)

// Mutex to prevent race conditions when accessing the clients map
var mu sync.Mutex

// Minimum time between messages to prevent flooding
const rateLimitInterval = 500 * time.Millisecond

// Client struct represents a connected user
type Client struct {
	Conn     net.Conn   // TCP connection
	Username string     // Username of the client
	LastSent time.Time  // Timestamp of last message (for rate limiting)
	IsAdmin  bool       // Whether the user has admin privileges
}

// initDB initializes the SQLite database and creates the users table if needed
func initDB() {
	var err error

	// Open (or create) SQLite database file
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create users table if it does not exist
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password TEXT,
		is_admin INTEGER DEFAULT 0,
		is_banned INTEGER DEFAULT 0
	);`

	_, err = db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	// Create default admin user (if not already exists)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("your_password"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	INSERT OR IGNORE INTO users (username, password, is_admin)
	VALUES (?, ?, 1)
	`, "YOUR_USERNAME", string(hashedPassword))
	if err != nil {
		log.Fatal(err)
	}
}

// validateUsername checks if username meets security rules
func validateUsername(username string) error {

	// Username length must be between 3 and 20 characters
	if len(username) < 3 || len(username) > 20 {
		return errors.New("username must be 3-20 characters")
	}

	// Only allow letters, numbers and underscore
	valid := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !valid.MatchString(username) {
		return errors.New("username contains invalid characters")
	}

	return nil
}

// broadcast sends a message to all connected users except the sender
func broadcast(sender, message string) {
	mu.Lock()
	defer mu.Unlock()

	for username, client := range clients {
		if username != sender {
			client.Conn.Write([]byte(sender + "> " + message + "\n"))
		}
	}
}

// privateMessage sends a message to a specific user
func privateMessage(sender, target, message string) {
	mu.Lock()
	defer mu.Unlock()

	if client, ok := clients[target]; ok {
		client.Conn.Write([]byte("(private) " + sender + "> " + message + "\n"))
	}
}

// removeClient safely removes a user from the online list
func removeClient(username string) {
	mu.Lock()
	defer mu.Unlock()

	if client, ok := clients[username]; ok {
		client.Conn.Close()
		delete(clients, username)
	}
}

// handleClient manages authentication and chat session
func handleClient(conn net.Conn) {

	defer conn.Close()
	reader := bufio.NewReader(conn)

	conn.Write([]byte("Connected to server\n"))
	conn.Write([]byte("1) Register\n2) Login\n> "))

	// Read user choice
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	// Ask for username
	conn.Write([]byte("Username: "))
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Validate username format
	if err := validateUsername(username); err != nil {
		conn.Write([]byte(err.Error() + "\n"))
		return
	}

	// Ask for password
	conn.Write([]byte("Password: "))
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	var storedPassword string
	var isAdmin, isBanned int

	// Registration flow
	if choice == "1" {

		// Hash password before storing
		hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			conn.Write([]byte("Server error.\n"))
			return
		}

		// Insert new user into database
		_, err = db.Exec("INSERT INTO users(username,password) VALUES(?,?)",
			username, string(hashed))

		if err != nil {
			conn.Write([]byte("User already exists.\n"))
			return
		}

		conn.Write([]byte("Registered successfully.\n"))

	} else {

		// Login flow
		err := db.QueryRow(
			"SELECT password,is_admin,is_banned FROM users WHERE username=?",
			username,
		).Scan(&storedPassword, &isAdmin, &isBanned)

		if err != nil {
			conn.Write([]byte("User not found.\n"))
			return
		}

		// Compare hashed password
		if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)) != nil {
			conn.Write([]byte("Wrong password.\n"))
			return
		}

		// Check if user is banned
		if isBanned == 1 {
			conn.Write([]byte("You are banned.\n"))
			return
		}

		conn.Write([]byte("Login successful.\n"))
	}

	// Prevent multiple logins with same username
	mu.Lock()
	if _, exists := clients[username]; exists {
		mu.Unlock()
		conn.Write([]byte("User already online.\n"))
		return
	}

	// Create new client object
	client := &Client{
		Conn:     conn,
		Username: username,
		LastSent: time.Now(),
		IsAdmin:  isAdmin == 1,
	}

	clients[username] = client
	mu.Unlock()

	// Notify others
	broadcast(username, "joined the chat")
	conn.Write([]byte("Welcome " + username + "\n"))

	// Main chat loop
	for {

		msg, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}

		// Rate limiting check
		if time.Since(client.LastSent) < rateLimitInterval {
			conn.Write([]byte("You are sending messages too fast.\n"))
			continue
		}
		client.LastSent = time.Now()

		// Command handling
		if msg == "/online" {
			mu.Lock()
			conn.Write([]byte("Online users:\n"))
			for user := range clients {
				conn.Write([]byte("- " + user + "\n"))
			}
			mu.Unlock()
			continue
		}

		if strings.HasPrefix(msg, "/msg ") {
			parts := strings.SplitN(msg, " ", 3)
			if len(parts) == 3 {
				privateMessage(username, parts[1], parts[2])
			}
			continue
		}

		// Admin commands
		if client.IsAdmin && strings.HasPrefix(msg, "/ban ") {
			target := strings.TrimPrefix(msg, "/ban ")
			db.Exec("UPDATE users SET is_banned=1 WHERE username=?", target)
			removeClient(target)
			conn.Write([]byte(target + " banned.\n"))
			continue
		}

		if client.IsAdmin && strings.HasPrefix(msg, "/unban ") {
			target := strings.TrimPrefix(msg, "/unban ")
			db.Exec("UPDATE users SET is_banned=0 WHERE username=?", target)
			conn.Write([]byte(target + " unbanned.\n"))
			continue
		}

		// Echo to sender
		conn.Write([]byte("you> " + msg + "\n"))

		// Broadcast to other users
		broadcast(username, msg)
	}

	// Cleanup when client disconnects
	removeClient(username)
	broadcast(username, "left the chat")
	fmt.Println(username + " disconnected")
}

func main() {

	// Initialize database
	initDB()

	// Start TCP server on port 1342
	listener, err := net.Listen("tcp", ":1342")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Println("Server running on 0.0.0.0:1342")
	fmt.Println("PID:", os.Getpid())

	// Accept connections in a loop
	for {
		conn, err := listener.Accept()
		if err == nil {
			go handleClient(conn) // Handle each client in a separate goroutine
		}
	}
}
