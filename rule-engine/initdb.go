// initdb.go
package main

import (
    "fmt"
    "os"
)

func main() {
    // Specify where you want the database to be created
    dataDir := "./reports" 
    if len(os.Args) > 1 {
        dataDir = os.Args[1]
    }

    // Create the directory if it doesn't exist
    if err := os.MkdirAll(dataDir, 0755); err != nil {
        fmt.Printf("Failed to create data directory: %v\n", err)
        os.Exit(1)
    }

    // Initialize the database
    db, err := NewDB(dataDir)
    if err != nil {
        fmt.Printf("Failed to initialize database: %v\n", err)
        os.Exit(1)
    }
    defer db.Close()

    fmt.Printf("Successfully initialized database at %s/data.db\n", dataDir)
}