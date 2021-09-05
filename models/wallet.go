package models

type Wallet struct {
	Mnemonic string `json:"mnemonic"`
	IsValidMnemonic bool `json:"is_valid_mnemonic"`
	Seed string `json:"seed"`
	ConfirmMnemonic string `json:"confirm_mnemonic"`
	ETHPrivateKey string `json:"eth_private_key"`
	IsValidETHPrivateKey bool `json:"is_valid_eth_priv_key"`
	ETHAddress string `json:"eth_address"`
}

// type Address 