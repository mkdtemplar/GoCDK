package main

import (
	"errors"
	"fmt"
	"labda-func/app"
	"labda-func/middleware"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type MyEvent struct {
	Username string `json:"username"`
}

// HandleRequests Take payload and do something with it
func HandleRequests(event MyEvent) (string, error) {
	if event.Username == "" {
		return "", errors.New("username is empty")
	}

	return fmt.Sprintf("Successfully called by - %s", event.Username), nil
}

func ProtectedHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{Body: "This is a secret path", StatusCode: 200}, nil
}

func main() {
	myApp := app.NewApp()
	lambda.Start(func(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		switch request.Path {
		case "/register":
			return myApp.ApiHandler.RegisterUserHandler(request)
		case "/login":
			return myApp.ApiHandler.LoginUser(request)
		case "/protected":
			return middleware.ValidateJWTMiddleware(ProtectedHandler)(request)
		default:
			return events.APIGatewayProxyResponse{Body: "Not Found", StatusCode: http.StatusNotFound}, nil
		}
	})

}
