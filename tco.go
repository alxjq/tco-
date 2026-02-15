package main

import (
    "bufio"
    "fmt"
    "net"
    "strings"
)

func handleClient(conn net.Conn) {
    defer conn.Close()

    // Ask for name
    conn.Write([]byte("Enter your name:\n> "))
    reader := bufio.NewReader(conn)
    name, _ := reader.ReadString('\n')
    name = strings.TrimSpace(name)
    fmt.Println("New client:", name)

    for {
        msg, err := reader.ReadString('\n')
        if err != nil {
            fmt.Println(name, "disconnected.")
            return
        }
        msg = strings.TrimSpace(msg)
        fmt.Printf("[%s]: %s\n", name, msg)
        conn.Write([]byte(msg + "\n")) // echo
    }
}

func main() {
    listener, err := net.Listen("tcp", ":8080")
    if err != nil {
        panic(err)
    }
    defer listener.Close()
    fmt.Println("Server listening on port 8080...")

    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Println("Error:", err)
            continue
        }
        go handleClient(conn) // Goroutine for multiple clients
    }
}
