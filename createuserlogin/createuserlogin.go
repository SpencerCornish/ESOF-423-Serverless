package createuserlogin

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

var ctx context.Context
var firestoreClient *firestore.Client
var authClient *auth.Client

func init() {

	// The correlation for this function run
	ctx = context.Background()

	// Get a new firebase app instance from the runtime context
	app, err := firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatalf("Error: failed to get firebase client: %v\n", err)
	}

	// Get a new firebase auth instance from the runtime context
	authClient, err = app.Auth(ctx)
	if err != nil {
		log.Fatalf("Error: failed to get firebase auth client: %v\n", err)
	}

	// Get a new firebase database instance from the runtime context
	firestoreClient, err = app.Firestore(ctx)
	if err != nil {
		log.Fatalf("Error: failed to get firebase firestore client: %v\n", err)
	}

}

// CreateUserLogin is the entrypoint for creating a login user
func CreateUserLogin(w http.ResponseWriter, r *http.Request) {

	// Add content request security headers
	head := w.Header()
	head.Add("Access-Control-Allow-Methods", "POST")
	head.Add("Access-Control-Allow-Headers", "true")
	head.Add("Access-Control-Allow-Origin", "*")

	// Create a new buffer, and read the incoming body payload
	buffer := new(bytes.Buffer)
	buffer.ReadFrom(r.Body)

	var load map[string]interface{}

	// Unmarshal the JSON into the `load` map
	err := json.Unmarshal(buffer.Bytes(), &load)
	if err != nil {
		log.Printf("Error: could not parse JSON payload: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the relevant data from the the payload map, and turn it into strings
	email := load["email"].(string)
	authorization := load["authorization"].(string)

	if email == "" || authorization == "" {
		fmt.Printf("Warning: incorrect payload: %v", load)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the token for the requesting user
	token, err := fetchAndValidateToken(ctx, authClient, authorization)
	if err != nil {
		log.Printf("Warning: Could not validate token: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check to see if this user is an admin and can create logins
	isAllowed, err := canUserCreateUsers(ctx, firestoreClient, token.UID)
	if err != nil {
		log.Printf("Error: unable to check if user can create users: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !isAllowed {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// At this point, we know we are allowed to create a new user

	params := (&auth.UserToCreate{}).
		Email(email).
		EmailVerified(false).
		Disabled(false)

	u, err := authClient.CreateUser(ctx, params)
	if err != nil {
		log.Printf("Error: creating user: %v\n", err)
		if auth.IsEmailAlreadyExists(err) {
			log.Printf("User already exists, all done")
			w.Write([]byte("EMAIL_EXISTS"))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("Successfully created user: %v\n", u.UID)

	w.Write([]byte(u.UID))
	w.WriteHeader(http.StatusCreated)
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

	userRole := userSlice[0].Data()["role"]
	if userRole == nil {
		return false, nil
	}

	// Only admins should be allowed to create new users
	if strings.ToLower(userRole.(string)) == "admin" {
		return true, nil
	}

	return false, nil
}

func fetchAndValidateToken(ctx context.Context, authClient *auth.Client, authHeader string) (*auth.Token, error) {

	// Trim off the bearer prefix
	authHeader = strings.TrimSpace(authHeader)
	authHeader = strings.TrimPrefix(authHeader, "Bearer ")

	token, err := authClient.VerifyIDToken(ctx, authHeader)
	if err != nil {
		log.Printf("error verifying ID token: %v\n", err)
		return nil, err
	}

	return token, nil
}
