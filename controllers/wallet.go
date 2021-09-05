package controllers

import (
	s "go/wallet-api/services"

	"github.com/gofiber/fiber/v2"
	"fmt"
)

func CreateNewWallet(c *fiber.Ctx) error {
	mnemonic, err := s.CreateWallet()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"success":  false,
			"message": "Error while creating wallet",
			"error": err,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success":  true,
		"payload": mnemonic,
	})
}

func ImportExistingWallet(c *fiber.Ctx) error {
	body := struct {
		Mnemonic string `json:"mnemonic"`
	}{}
	
	if err := c.BodyParser(&body); err != nil {
		return err
	}

	err := s.ImportWallet(body.Mnemonic)
	if err != nil {
		fmt.Println(err)
		return c.Status(302).JSON(fiber.Map{
			"success":  false,
			"message": "Error while importing wallet, recheck mnemonics",
			"err": err,
		})
	}

	// get coin address
	addresses, err := s.GetCoinAddressForAWallet(body.Mnemonic)
	if err != nil {
		return c.Status(302).JSON(fiber.Map{
		"success":  false,
		"message": "Error while getting coin address for wallet",
		"err": err,
		})
	}

	return c.Status(200).JSON(fiber.Map{
		"success": true,
		"message": "Wallet imported successfully",
		"addresses": addresses,
	})
}

func SendETH(c *fiber.Ctx) error {
	body := struct {
		Mnemonic string `json:"mnemonic"`
		ReceiverAddress string `json:"receiverAddress"`
		Amount string `json:"amount"`
	}{}
	
	if err := c.BodyParser(&body); err != nil {
		return err
	}

	response, err := s.SendETH(body.Mnemonic, body.ReceiverAddress, body.Amount)

	if err != nil {
		return c.Status(302).JSON(fiber.Map{
		"success":  false,
		"err": err.Error(),
		})
	}

	return c.Status(201).JSON(fiber.Map{
		"response": response,
	})
}

func SendERC20(c *fiber.Ctx) error {
	body := struct {
		Mnemonic string `json:"mnemonic"`
		ReceiverAddress string `json:"receiverAddress"`
		Amount string `json:"amount"`
		Token string `json:"token"`
	}{}

	if err := c.BodyParser(&body); err != nil {
		return err
	}

	response, err := s.SendSelectedToken(body.Mnemonic, body.ReceiverAddress, body.Amount, body.Token)

	if err != nil {
		return c.Status(302).JSON(fiber.Map{
		"success":  false,
		"err": err.Error(),
		})
	}

	return c.Status(201).JSON(fiber.Map{
		"response": response,
	})
}