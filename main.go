package main

import (
	"log"
	// "os"
	// "os"
	// "fmt"

	"go/wallet-api/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	// "github.com/joho/godotenv"
)

func setupRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"success": true,
			"message": "You are at the root endpoint 😉",
		})
	})

	api := app.Group("/api")

	routes.WalletRoute(api.Group("/"))
}

func main() {
	// if os.Getenv("APP_ENV") != "production" {
	// 	err := godotenv.Load()
	// 	if err != nil {
	// 		log.Fatal("Error loading .env file")
	// 	}
	// }

	app := fiber.New(fiber.Config{})

	app.Use(cors.New())
	app.Use(logger.New())

	setupRoutes(app)

	port := "8080"
	err := app.Listen(":" + port)

	if err != nil {
		log.Fatal("Error app failed to start")
		panic(err)
	}
}
