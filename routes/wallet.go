package routes

import (
	c "go/wallet-api/controllers"

	"github.com/gofiber/fiber/v2"
)

func WalletRoute(route fiber.Router) {
	route.Get("/create", c.CreateNewWallet)
	route.Post("/import", c.ImportExistingWallet)
	route.Post("/generate-address", c.GenerateAddress)
	route.Post("/send/eth", c.SendETH)
	route.Post("/send/erc20", c.SendERC20)
	route.Get("/coin-list", c.CoinList)
}
