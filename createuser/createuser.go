package createuser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
)

type payload struct {
	email         string
	authorization string
}

// CreateAuthUser is the entrypoint for creating a login user
func CreateAuthUser(w http.ResponseWriter, r *http.Request) {

	head := w.Header()
	head.Add("Access-Control-Allow-Methods", "POST, GET")
	head.Add("Access-Control-Allow-Headers", "true")
	head.Add("Access-Control-Allow-Origin", "*")

	ctx := context.Background()

	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		log.Printf("Error: failed to get firebase client: %v\n", err)
		w.WriteHeader(500)
		return
	}

	authClient, err := app.Auth(ctx)
	if err != nil {
		log.Printf("Error: failed to get firebase auth client: %v\n", err)
		w.WriteHeader(500)
		return
	}

	body := r.Body

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(body)

	var load map[string]interface{}

	err = json.Unmarshal(buffer.Bytes(), &load)

	fmt.Printf("JSON: %v", load)

	// TODO: Test error here

	token, errCode, err := fetchAndValidateToken(ctx, authClient, load["authorization"].(string))
	if err != nil {
		log.Printf("Warning: Could not validate token: %v", err)
		w.WriteHeader(errCode)
		return
	}
	log.Printf("This token's UID: %s", token.UID)

	if load["email"].(string) == "" {
		fmt.Printf("Warning: Email not included")
		w.WriteHeader(400)
		return
	}

	firestoreClient, err := app.Firestore(ctx)
	if err != nil {
		log.Printf("Error: failed to get firebase firestore client: %v\n", err)
		w.WriteHeader(500)
		return
	}

	isAllowed, err := canUserCreateUsers(ctx, firestoreClient, token.UID)
	if err != nil {
		log.Printf("Error: unable to check if user can create users: %v", err)
		w.WriteHeader(500)
		return
	}

	if !isAllowed {
		w.WriteHeader(402)
		return
	}

	// At this point, we know we are allowed to create a new user

	params := (&auth.UserToCreate{}).
		Email(load["email"].(string)).
		EmailVerified(false).
		Disabled(false)
	u, err := authClient.CreateUser(ctx, params)
	if err != nil {
		log.Fatalf("error creating user: %v\n", err)
	}
	log.Printf("Successfully created user: %v\n", u)

	w.Write([]byte(u.UID))
	w.WriteHeader(200)
}

func canUserCreateUsers(ctx context.Context, client *firestore.Client, uid string) (bool, error) {
	// Get the userdata from which this request originated
	matchingUsers := client.Collection("users").Where("login_uid", "==", uid).Documents(ctx)

	userSlice, err := matchingUsers.GetAll()
	if err != nil {
		return false, err
	}
	if len(userSlice) != 1 {
		if len(userSlice) > 1 {
			log.Printf("CRITICAL: Duplicate login_uids: %s", uid)
		}
		return false, nil
	}

	userData := userSlice[0].Data()

	userRole := userData["role"]
	if userRole == nil {
		return false, nil
	}

	// Only admins should be allowed to create new users
	if strings.ToLower(userRole.(string)) == "admin" {
		return true, nil
	}

	return false, nil
}

func fetchAndValidateToken(ctx context.Context, authClient *auth.Client, authHeader string) (*auth.Token, int, error) {

	// Trim off the bearer prefix

	authHeader = strings.TrimSpace(authHeader)
	authHeader = strings.TrimPrefix(authHeader, "Bearer ")

	token, err := authClient.VerifyIDToken(ctx, authHeader)
	if err != nil {
		log.Printf("error verifying ID token: %v\n", err)
		return nil, 403, err
	}

	return token, 200, nil
}
