package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/shindakun/bskyoauth"
)

func main() {
	// This example shows how to use the CreateRecord and DeleteRecord methods
	// to work with custom collections like club.ongaku.prototype

	// Initialize client
	client := bskyoauth.NewClient("http://localhost:8181")

	// In a real application, you would get the session from your session store
	// after the user has logged in via OAuth
	sessionID := "your-session-id"
	session, err := client.GetSession(sessionID)
	if err != nil {
		log.Fatal("No session found. Please log in first.")
	}

	ctx := context.Background()

	// Example 1: Create a record in club.ongaku.prototype collection
	fmt.Println("Creating a new club.ongaku.prototype record...")
	record := map[string]interface{}{
		"text":      "This is a prototype record!",
		"createdAt": time.Now().Format(time.RFC3339),
	}

	output, err := client.CreateRecord(ctx, session, "club.ongaku.prototype", record)
	if err != nil {
		log.Fatalf("Failed to create record: %v", err)
	}

	fmt.Printf("Record created successfully!\n")
	fmt.Printf("URI: %s\n", output.Uri)
	fmt.Printf("CID: %s\n", output.Cid)

	// The rkey (record key) is the last part of the URI
	// e.g., at://did:plc:xxx/club.ongaku.prototype/3k... -> rkey is "3k..."
	rkey := output.Uri[len(output.Uri)-13:] // Extract rkey from URI

	// Example 2: Delete the record
	fmt.Println("\nDeleting the record...")
	err = client.DeleteRecord(ctx, session, "club.ongaku.prototype", rkey)
	if err != nil {
		log.Fatalf("Failed to delete record: %v", err)
	}

	fmt.Println("Record deleted successfully!")
}
