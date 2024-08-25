package app

import (
	"labda-func/api"
	"labda-func/database"
)

type App struct {
	ApiHandler *api.ApiHandler
}

func NewApp() *App {
	db := database.NewDynamoDBClient()
	apiHandler := api.NewApiHandler(db)
	return &App{ApiHandler: apiHandler}
}
