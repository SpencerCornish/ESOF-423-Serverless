package removeuserlogin

import (
	"context"
	"log"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
)

// FirestoreEvent is the payload of a Firestore event.
type FirestoreEvent struct {
	OldValue   FirestoreValue `json:"oldValue"`
	Value      FirestoreValue `json:"value"`
	UpdateMask struct {
		FieldPaths []string `json:"fieldPaths"`
	} `json:"updateMask"`
}

// FirestoreValue holds Firestore fields.
type FirestoreValue struct {
	CreateTime time.Time `json:"createTime"`
	// Fields is the data for this value. The type depends on the format of your
	// database. Log the interface{} value and inspect the result to see a JSON
	// representation of your database fields.
	Fields     interface{} `json:"fields"`
	Name       string      `json:"name"`
	UpdateTime time.Time   `json:"updateTime"`
}

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

// RemoveUserLogin is the entrypoint for when a user is deleted. This simply removes the user from the login list,
// if they had a login provisioned.
func RemoveUserLogin(ctx context.Context, e FirestoreEvent) error {

	fieldMap := e.OldValue.Fields.(map[string]interface{})

	deletedUserLoginUID := fieldMap["login_uid"].(map[string]interface{})["stringValue"].(string)
	if deletedUserLoginUID == "" {
		log.Printf("Deleted user did not have a login uid. Exiting")
		return nil
	}

	err := authClient.DeleteUser(ctx, deletedUserLoginUID)
	if err != nil {
		if auth.IsUserNotFound(err) {
			log.Printf("User was not found, so nothing to do. Exiting: %v", err)
			return nil
		}
		log.Fatalf("Error deleting user record: %v", err)
	}

	return nil
}
