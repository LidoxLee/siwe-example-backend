package main

import (
	"errors"
	"fmt"
	"log"
	"siwe-example/util"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/spruceid/siwe-go"
)

// verifyWalletSignature verifies the signature of a wallet address
func verifyWalletSignature(wallet string, messageStr string, sig string) (jwt.MapClaims, error) {

	message, err := siwe.ParseMessage(messageStr)
	if err != nil {
		err = fmt.Errorf("parse message err: %v", err)
		return nil, err
	}

	verify, err := message.ValidNow()
	if err != nil {
		err = fmt.Errorf("verify message err: %v", err)
		return nil, err
	}

	if !verify {
		err = fmt.Errorf("verify message fail: %v", err)
		return nil, err
	}

	publicKey, err := message.VerifyEIP191(sig)

	if err != nil {
		err = fmt.Errorf("verifyEIP191 err: %v", err)
		return nil, err
	}

	pubBytes := crypto.FromECDSAPub(publicKey)
	publicKeyString := hexutil.Encode(pubBytes)

	// Get the Ethereum address from the public key
	recoveredAddress := crypto.PubkeyToAddress(*publicKey).Hex()

	// Compare the recovered address to the expected address
	if recoveredAddress != wallet {
		err = errors.New("recoverd address not correct")
		return nil, err
	}

	// Return the verified claims
	claims := jwt.MapClaims{
		"user_wallet":  wallet,
		"web3_pub_key": publicKeyString,
	}
	return claims, nil
}

// LoginRequest represents the login request body
type LoginRequest struct {
	UserWallet string `json:"userWallet"`
	Message    string `json:"message"`
	Sig        string `json:"sig"`
}

func Web3Login(c *fiber.Ctx) error {
	// Parse the login request body
	req := new(LoginRequest)
	if err := c.BodyParser(req); err != nil {
		return err
	}

	// Verify the wallet signature
	claims, err := verifyWalletSignature(req.UserWallet, req.Message, req.Sig)
	if err != nil {
		err = errors.New("verify wallet fail")
		return c.JSON(fiber.Map{
			"success": false,
			"error":   err.Error(),
		})
	}
	fmt.Print(claims)

	tokenString, err := util.GenerateJwt(claims["user_wallet"].(string))
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Success Login",
		"jwt":     tokenString,
	})
}

func Setup(app *fiber.App) {
	app.Post("/auth/web3", Web3Login)
}

func main() {
	app := fiber.New()

	Setup(app)

	if err := app.Listen(":8000"); err != nil {
		log.Fatal(err)
	}
}
