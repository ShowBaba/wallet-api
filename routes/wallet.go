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
	route.Post("/balance/eth", c.ETHAddressBalance)
	route.Post("/balance/erc20", c.ERC20TokenBalance)
	route.Get("/coin-list", c.CoinList)
	route.Post("/send/bnb", c.SendBNB)
	route.Post("/send/btc", c.SendBTC)
}
