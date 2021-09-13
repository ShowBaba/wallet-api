package models

type Transaction struct {
	From string `json:"from"`
	To string `json:"to"`
	Amount string `json:"amount"`
	GasPrice string `json:"gasPrice"`
	Nonce string `json:"nonce"`
	Hash string `json:"hash"`
}

type BTCTransaction struct {
	From string `json:"from"`
	To string `json:"to"`
	Amount int64 `json:"amount"`
	Hash string `json:"hash"`
}