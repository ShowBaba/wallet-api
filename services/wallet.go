package services

/*
#cgo CFLAGS: -I/wallet-core/include
#cgo LDFLAGS: -L/wallet-core/build -L/wallet-core/build/trezor-crypto -lTrustWalletCore -lprotobuf -lTrezorCrypto -lc++ -lm
#include <TrustWalletCore/TWHDWallet.h>
#include <TrustWalletCore/TWString.h>
#include <TrustWalletCore/TWData.h>
#include <TrustWalletCore/TWPrivateKey.h>
#include <TrustWalletCore/TWPublicKey.h>
#include <TrustWalletCore/TWMnemonic.h>
#include <TrustWalletCore/TWBitcoinScript.h>
#include <TrustWalletCore/TWAnySigner.h>
*/
import "C"

import (
	m "go/wallet-api/models"
	h "go/wallet-api/helpers"
	// "go/wallet-api/protos/bitcoin"

	// "github.com/tyler-smith/go-bip39"
	// "github.com/golang/protobuf/proto"

	// eth
	// "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	// "github.com/ethereum/go-ethereum/accounts/abi/bind"
	// "github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/sha3"
	"github.com/ethereum/go-ethereum/common/hexutil"
	
	"math/big"
	"crypto/ecdsa"
	// "bytes"
	// "unsafe"
	"encoding/hex"
	"fmt"
	"log"
	"errors"
	// "math"
	// "strings"
	"strconv"
	"context"
)

var InfuraUrl = "https://kovan.infura.io/v3/342f979e9d594a0ea51404cf3841eafa"
// var ganacheUrl = "HTTP://127.0.0.1:8545"

func CreateWallet() (*string, error) {
	// create wallet and return wallet mnemonic
	mnemonic, err := h.GenerateMnemonic()
	if err != nil {
		return nil, err
	}

	// convert mnemonic from Go String to C.TWString
	str := h.TWStringCreateWithGoString(*mnemonic);
	empty := h.TWStringCreateWithGoString("")
	defer C.TWStringDelete(str)
	defer C.TWStringDelete(empty)

	// verify if mnemonic is valid
	isValidMnemonic := h.MnemonicIsValid(*mnemonic)
	if isValidMnemonic == false {
		return nil, errors.New("Invalid Mnemonic")
	}

	return mnemonic, nil
}

func ImportWallet(mnemonic string) error {
	isValidMnemonic := h.MnemonicIsValid(mnemonic)
	if isValidMnemonic == false {
		return errors.New("Invalid Mnemonics")
	}

	str := h.TWStringCreateWithGoString(mnemonic);
	empty := h.TWStringCreateWithGoString("")
	defer C.TWStringDelete(str)
	defer C.TWStringDelete(empty)

	wallet := C.TWHDWalletCreateWithMnemonic(str, empty)
	defer C.TWHDWalletDelete(wallet)

	walletMnemonic := C.TWHDWalletMnemonic(wallet)
	if mnemonic != h.TWStringGoString(walletMnemonic) {
		return errors.New("Mnemonics does'nt match")
	}

	return nil
}

func CoinList() []string {
	coins := []string{
		"AE",	"AION", "BNB","BTC","BTG","CLO","ADA","ATOM","DASH","DCR","DGB","DOGE","EOS","ETH","ETC",
		"FIO","GO","GRS","ICX","IOTX","KAVA","KIN","LTC","MONA","NAS","NULS","NANO","NEAR","NIM","ONT","POA",
		"QTUM","XRP","SOL","XLM","XTZ","THETA","TT","NEO","TOMO","TRX","VET","VIA","WAN","ZEC","XZC","ZIL","FLUX",
		"RVN","WAVES","LUNA","ONE","ALGO","KSM","DOT","FIL","ERD","BAND","ROSE","MATIC","RUNE","BNT",
	}
	return coins
}

func GetCoinAddressForAWallet(mnemonic string, coinType string) (map[string]string, error) {
	fmt.Println("Fetching coin address for wallet")
	coins := map[string]uint32{
		"AE": C.TWCoinTypeAeternity,"AION": C.TWCoinTypeAion,"BNB":  C.TWCoinTypeBinance,"BTC":  C.TWCoinTypeBitcoin,"BTG":  C.TWCoinTypeBitcoinGold,"CLO":  C.TWCoinTypeCallisto,
		"ADA":  C.TWCoinTypeCardano,"ATOM":  C.TWCoinTypeCosmos,"DASH":  C.TWCoinTypeDash,"DCR":  C.TWCoinTypeDecred,"DGB":  C.TWCoinTypeDigiByte,"DOGE":  C.TWCoinTypeDogecoin,"EOS":  C.TWCoinTypeEOS,
		"ETH":  C.TWCoinTypeEthereum,"ETC":  C.TWCoinTypeEthereumClassic,"FIO":  C.TWCoinTypeFIO,"GO":  C.TWCoinTypeGoChain,"GRS":  C.TWCoinTypeGroestlcoin,"ICX":  C.TWCoinTypeICON,"IOTX":  C.TWCoinTypeIoTeX,"KAVA":  C.TWCoinTypeKava,
		"KIN":  C.TWCoinTypeKin,"LTC":  C.TWCoinTypeLitecoin,"MONA":  C.TWCoinTypeMonacoin,"NAS":  C.TWCoinTypeNebulas,"NULS":  C.TWCoinTypeNULS,"NANO":  C.TWCoinTypeNano,"NEAR":  C.TWCoinTypeNEAR,"NIM":  C.TWCoinTypeNimiq,"ONT":  C.TWCoinTypeOntology,
		"POA":  C.TWCoinTypePOANetwork,"QTUM":  C.TWCoinTypeQtum,"XRP":  C.TWCoinTypeXRP,"SOL":  C.TWCoinTypeSolana,"XLM":  C.TWCoinTypeStellar,"XTZ":  C.TWCoinTypeTezos,"THETA":  C.TWCoinTypeTheta,"TT":  C.TWCoinTypeThunderToken,"NEO":  C.TWCoinTypeNEO,
		"TOMO":  C.TWCoinTypeTomoChain,"TRX":  C.TWCoinTypeTron,"VET":  C.TWCoinTypeVeChain,"VIA":  C.TWCoinTypeViacoin,"WAN":  C.TWCoinTypeWanchain,"ZEC":  C.TWCoinTypeZcash,"XZC":  C.TWCoinTypeZcoin,"ZIL":  C.TWCoinTypeZilliqa,"FLUX":  C.TWCoinTypeZelcash,"RVN":  C.TWCoinTypeRavencoin,
		"WAVES":  C.TWCoinTypeWaves,"LUNA":  C.TWCoinTypeTerra,"ONE":  C.TWCoinTypeHarmony,"ALGO":  C.TWCoinTypeAlgorand,"KSM":  C.TWCoinTypeKusama,"DOT":  C.TWCoinTypePolkadot,"FIL":  C.TWCoinTypeFilecoin,"ERD":  C.TWCoinTypeElrond,
		"BAND":  C.TWCoinTypeBandChain,"ROSE":  C.TWCoinTypeOasis,"MATIC":  C.TWCoinTypePolygon,"RUNE":  C.TWCoinTypeTHORChain,"BNT":  C.TWCoinTypeBluzelle,
	}

	str := h.TWStringCreateWithGoString(mnemonic);
	empty := h.TWStringCreateWithGoString("")
	defer C.TWStringDelete(str)
	defer C.TWStringDelete(empty)
	wallet := C.TWHDWalletCreateWithMnemonic(str, empty)
	defer C.TWHDWalletDelete(wallet)

	
	var addressMap = make(map[string]string)
	
	// get address for coin 
	// for coin, element := range coins {
		address := C.TWHDWalletGetAddressForCoin(wallet, coins[coinType])
		addressStr := h.TWStringGoString(address)
		addressMap[coinType] = addressStr
		
		// GET BALANCE
	// client,  err := ethclient.Dial(InfuraUrl)
	// if err != nil {
	// 	fmt.Println("Unable to connect to network:%v \n", err)
	// 	return nil, err
	// }
	// account := common.HexToAddress(addressStr)
	// balance, err := client.BalanceAt(context.Background(), account, nil)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fbalance := new(big.Float)
	// fbalance.SetString(balance.String())
	// ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
	// fmt.Println(ethValue)
	// }
	return addressMap, nil
}


func SendETH(mnemonic string, receiverAddressHex string, inAmount string)(interface{}, error){
	var t m.Transaction

	client,  err := ethclient.Dial(InfuraUrl)
	if err != nil {
		fmt.Println("Unable to connect to network:%v \n", err)
		return nil, err
	}

	str := h.TWStringCreateWithGoString(mnemonic)
	empty := h.TWStringCreateWithGoString("")
	defer C.TWStringDelete(str)
	defer C.TWStringDelete(empty)

	wallet := C.TWHDWalletCreateWithMnemonic(str, empty)
	defer C.TWHDWalletDelete(wallet)

	// prepair privatekey
	key := C.TWHDWalletGetKeyForCoin(wallet, C.TWCoinTypeEthereum)
	keyData := C.TWPrivateKeyData(key)
	privateKey := hex.EncodeToString(h.TWDataGoBytes(keyData))


	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// get public key from private key by casting the private key eliptic curve DSA format
	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		return nil, err
	}

	// get the ethereum address from the extracted public key
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println("From address: ", fromAddress)
	t.From = fromAddress.String()

	// TODO: check balance against sending amount;
	// check balance
	balance, err := h.GetWeiBalance(fromAddress.String(), client);
	fmt.Println("Balance: ", balance)
	if err != nil {
			log.Fatal("error while fetching sender address balance")
			return nil, err
	}
	if balance.Cmp(big.NewInt(0)) == 0 {
		fmt.Println(">>>>> Available balance = ", balance, " <<<<<")
		return nil, errors.New("Insufficient funds")
	}

	
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		// log.Fatal(err)
		return nil, err
	}
	
	t.Nonce = strconv.FormatUint(nonce, 10)

	// convert amount
	value, err := h.ParseBigFloat(inAmount)
	if err != nil {
		return nil, errors.New("error while converting amount")
	}
	t.Amount = inAmount + "ETH"

	// convert to wei
	amount := h.EtherToWei(value)

	gasLimit := uint64(21000)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, errors.New("error while fetching suggested gasPrice")
	}
	
	toAddress := common.HexToAddress(receiverAddressHex)
	t.To = receiverAddressHex
	
	var data []byte
	
	tx := types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, data)
	
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, privateKeyECDSA)
	if err != nil {
		return nil, errors.New("error while signing transaction")	
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, errors.New("error while sending signed transaction")
	}

	t.Hash = signedTx.Hash().Hex()
	
	return t, nil
}

func SendERC20s(tokenAddress string, mnemonic string, receiverAddressHex string, inAmount string, token string)(interface{}, error){
	var t m.Transaction

	client,  err := ethclient.Dial(InfuraUrl)
	if err != nil {
		fmt.Println("Unable to connect to network:%v \n", err)
		return nil, err
	}

	str := h.TWStringCreateWithGoString(mnemonic)
	empty := h.TWStringCreateWithGoString("")
	defer C.TWStringDelete(str)
	defer C.TWStringDelete(empty)

	wallet := C.TWHDWalletCreateWithMnemonic(str, empty)
	defer C.TWHDWalletDelete(wallet)

	// prepair privatekey
	key := C.TWHDWalletGetKeyForCoin(wallet, C.TWCoinTypeEthereum)
	keyData := C.TWPrivateKeyData(key)
	privateKey := hex.EncodeToString(h.TWDataGoBytes(keyData))


	privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// get public key from private key by casting the private key eliptic curve DSA format
	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		return nil, err
	}

	// get the ethereum address from the extracted public key
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	fmt.Println("From address: ", fromAddress)
	t.From = fromAddress.String()

	// TODO: check balance against sending amount;
	// check balance
	// ttokenAddress := common.HexToAddress("0x33c77ebbf799a46a3112ea3021b540afa4c3be27")
	// instance, err := token.NewToken(ttokenAddress, client)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// taddress := common.HexToAddress("0x65D4E4A40f970304c24216BD1C86977B45D6d090")
	// bal, err := instance.BalanceOf(&bind.CallOpts{}, taddress)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Printf("Token Balance: %s\n", bal)
	balance, err := h.GetWeiBalance(fromAddress.String(), client);
	fmt.Println("Balance: ", balance)
	if err != nil {
			log.Fatal("error while fetching sender address balance")
			return nil, err
	}
	if balance.Cmp(big.NewInt(0)) == 0 {
		fmt.Println(">>>>> Available balance = ", balance, " <<<<<")
		return nil, errors.New("Insufficient funds")
	}

	
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		// log.Fatal(err)
		return nil, err
	}
	
	t.Nonce = strconv.FormatUint(nonce, 10)

	value := big.NewInt(0) // in wei (0 eth)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, errors.New("error while fetching suggested gasPrice")
	}
	
	toAddress := common.HexToAddress(receiverAddressHex)
	t.To = receiverAddressHex	

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]
	fmt.Println("Token MethodID: ",hexutil.Encode(methodID))

	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	fmt.Println("Padded Address: ",hexutil.Encode(paddedAddress))
	
	// convert amount
	flaotAmount, err := h.ParseBigFloat(inAmount)
	if err != nil {
		return nil, errors.New("error while converting amount")
	}
	// convert to wei
	amount := h.EtherToWei(flaotAmount)
	fmt.Println("Amount: ", amount, inAmount)
	t.Amount = inAmount + token

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	fmt.Println("Padded Amount: ",hexutil.Encode(paddedAmount))

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	// gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
	// 	To:   &toAddress,
	// 	Data: data,
	// })
	// if err != nil {
	// 	return nil, errors.New("Error estimating Gas Limit")
	// }
	gasLimit := uint64(77380)
	fmt.Println("gasLimit: ", gasLimit) 

	tx := types.NewTransaction(nonce, common.HexToAddress(tokenAddress), value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, errors.New("Error retriving Network ChainID")
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKeyECDSA)
	if err != nil {
		return nil, errors.New("Error signing transaction")
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, errors.New("Error sending transaction")
	}

	t.Hash = signedTx.Hash().Hex()

	return t, nil
}

func SendSelectedToken(mnemonic string, receiverAddress string, inAmount string, token string)(interface{}, error){
	switch token {
	case "BNB":
		fmt.Println("Selected Token: DAI")
		tokenAddress := "0xB8c77482e45F1F44dE1745F52C74426C631bDD52"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "USDT":
		fmt.Println("Selected Token: USDT")
		tokenAddress := "0xdac17f958d2ee523a2206206994597c13d831ec7"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "USDC":
		fmt.Println("Selected Token: USDC")
		tokenAddress := "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DAI":
		fmt.Println("Selected Token: DAI")
		tokenAddress := "0x6b175474e89094c44da98b954eedeac495271d0f"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ENJ":
		fmt.Println("Selected Token: ENJ")
		tokenAddress := "0xf629cbd94d3791c9250152bd8dfbdf380e2a3b9c"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SAND":
		fmt.Println("Selected Token: SAND")
		tokenAddress := "0x3845badAde8e6dFF049820680d1F14bD3903a5d0"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ANT":
		fmt.Println("Selected Token: ANT")
		tokenAddress := "0xa117000000f279d81a1d3cc75430faa017fa5a2e"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CLV":
		fmt.Println("Selected Token: CLV")
		tokenAddress := "0x80C62FE4487E1351b47Ba49809EBD60ED085bf52"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CHR":
		fmt.Println("Selected Token: CHR")
		tokenAddress := "0x8a2279d4a90b6fe1c4b30fa660cc9f926797baa2"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LIT":
		fmt.Println("Selected Token: LIT")
		tokenAddress := "0xb59490ab09a0f526cc7305822ac65f2ab12f9723"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "NWC":
		fmt.Println("Selected Token: NWC")
		tokenAddress := "0x968f6f898a6df937fc1859b323ac2f14643e3fed"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "RFOX":
		fmt.Println("Selected Token: RFOX")
		tokenAddress := "0xa1d6df714f91debf4e0802a542e13067f31b8262"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "TRU":
		fmt.Println("Selected Token: TRU")
		tokenAddress := "0x4c19596f5aaff459fa38b0f7ed92f11ae6543784"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DVI":
		fmt.Println("Selected Token: DVI")
		tokenAddress := "0x10633216e7e8281e33c86f02bf8e565a635d9770"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BEL":
		fmt.Println("Selected Token: BEL")
		tokenAddress := "0xa91ac63d040deb1b7a5e4d4134ad23eb0ba07e14"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "EXRD":
		fmt.Println("Selected Token: EXRD")
		tokenAddress := "0x6468e79A80C0eaB0F9A2B574c8d5bC374Af59414"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ASTA":
		fmt.Println("Selected Token: ASTA")
		tokenAddress := "0xf2ddae89449b7d26309a5d54614b1fc99c608af5"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LOTTO":
		fmt.Println("Selected Token: LOTTO")
		tokenAddress := "0xb0dFd28d3CF7A5897C694904Ace292539242f858"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ERC20":
		fmt.Println("Selected Token: ERC20")
		tokenAddress := "0xc3761eb917cd790b30dad99f6cc5b4ff93c4f9ea"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "UNCX":
		fmt.Println("Selected Token: UNCX")
		tokenAddress := "0xaDB2437e6F65682B85F814fBc12FeC0508A7B1D0"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CAPS":
		fmt.Println("Selected Token: CAPS")
		tokenAddress := "0x03be5c903c727ee2c8c4e9bc0acc860cca4715e2"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "AXIS":
		fmt.Println("Selected Token: AXIS")
		tokenAddress := "0xF0c5831EC3Da15f3696B4DAd8B21c7Ce2f007f28"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "PPAY":
		fmt.Println("Selected Token: PPAY")
		tokenAddress := "0x054d64b73d3d8a21af3d764efd76bcaa774f3bb2"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DON":
		fmt.Println("Selected Token: DON")
		tokenAddress := "0x217ddead61a42369a266f1fb754eb5d3ebadc88a"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "HYVE":
		fmt.Println("Selected Token: HYVE")
		tokenAddress := "0xd794DD1CAda4cf79C9EebaAb8327a1B0507ef7d4"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CBC":
		fmt.Println("Selected Token: CBC")
		tokenAddress := "0x26DB5439F651CAF491A87d48799dA81F191bDB6b"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "MARK":
		fmt.Println("Selected Token: MARK")
		tokenAddress := "0x67c597624b17b16fb77959217360b7cd18284253"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "MARSH":
		fmt.Println("Selected Token: MARSH")
		tokenAddress := "0x5a666c7d92E5fA7Edcb6390E4efD6d0CDd69cF37"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "XFT":
		fmt.Println("Selected Token: XFT")
		tokenAddress := "0xabe580e7ee158da464b51ee1a83ac0289622e6be"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "UNISTAKE":
		fmt.Println("Selected Token: UNISTAKE")
		tokenAddress := "0x9ed8e7c9604790f7ec589f99b94361d8aab64e5e"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "NOW":
		fmt.Println("Selected Token: NOW")
		tokenAddress := "0xe9a95d175a5f4c9369f3b74222402eb1b837693b"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "FOC":
		fmt.Println("Selected Token: FOC")
		tokenAddress := "0x3051CFb958dcD408FBa70256073Adba943Fdf552"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "UTU":
		fmt.Println("Selected Token: UTU")
		tokenAddress := "0xa58a4f5c4bb043d2cc1e170613b74e767c94189b"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "AVT":
		fmt.Println("Selected Token: AVT")
		tokenAddress := "0x0d88ed6e74bbfd96b831231638b66c05571e824f"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "8PAY":
		fmt.Println("Selected Token: 8PAY")
		tokenAddress := "0xFeea0bDd3D07eb6FE305938878C0caDBFa169042"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "TAP":
		fmt.Println("Selected Token: TAP")
		tokenAddress := "0x7f1f2d3dfa99678675ece1c243d3f7bc3746db5d"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SMI":
		fmt.Println("Selected Token: SMI")
		tokenAddress := "0xCd7492db29E2ab436e819b249452EE1bbDf52214"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LONDON":
		fmt.Println("Selected Token: LONDON")
		tokenAddress := "0x491d6b7d6822d5d4bc88a1264e1b47791fd8e904"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DTH":
		fmt.Println("Selected Token: DTH")
		tokenAddress := "0x5adc961d6ac3f7062d2ea45fefb8d8167d44b190"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ZUM":
		fmt.Println("Selected Token: ZUM")
		tokenAddress := "0xe0b9bcd54bf8a730ea5d3f1ffce0885e911a502c"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YVS":
		fmt.Println("Selected Token: YVS")
		tokenAddress := "0xec681f28f4561c2a9534799aa38e0d36a83cf478"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LMY":
		fmt.Println("Selected Token: LMY")
		tokenAddress := "0x66fd97a78d8854fec445cd1c80a07896b0b4851f"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YETH":
		fmt.Println("Selected Token: YETH")
		tokenAddress := "0xD387f0E62E3f123A54Ae486056A5D859AFFeD0c8"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DYNMT":
		fmt.Println("Selected Token: DYNMT")
		tokenAddress := "0x3b7f247f21bf3a07088c2d3423f64233d4b069f7"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CORX":
		fmt.Println("Selected Token: CORX")
		tokenAddress := "0x26a604DFFE3ddaB3BEE816097F81d3C4a2A4CF97"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CBIX":
		fmt.Println("Selected Token: CBIX")
		tokenAddress := "0x122f96d596384885b54bccdddf2125018c421d83"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CPR":
		fmt.Println("Selected Token: CPR")
		tokenAddress := "0x20ae0ca9d42e6ffeb1188f341a7d63450452def6"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "MCC":
		fmt.Println("Selected Token: MCC")
		tokenAddress := "0xaa625d0f31e99dcd1e9ff744073a9d16ce174de4"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "FEG":
		fmt.Println("Selected Token: FEG")
		tokenAddress := "0x389999216860ab8e0175387a0c90e5c52522c945"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "UNCL":
		fmt.Println("Selected Token: UNCL")
		tokenAddress := "0x2f4eb47a1b1f4488c71fc10e39a4aa56af33dd49"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "GFARM2":
		fmt.Println("Selected Token: GFARM2")
		tokenAddress := "0x831091dA075665168E01898c6DAC004A867f1e1B"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BEC":
		fmt.Println("Selected Token: BEC")
		tokenAddress := "0x59c033ec65e6b9c501c1ee34fb42f2575da4b517"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SMBSWAP":
		fmt.Println("Selected Token: SMBSWAP")
		tokenAddress := "0x53bd789f2cdb846b227d8ffc7b46ed4263231fdf"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LIME":
		fmt.Println("Selected Token: LIME")
		tokenAddress := "0x9d0b65a76274645b29e4cc41b8f23081fa09f4a3"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "MVEDA":
		fmt.Println("Selected Token: MVEDA")
		tokenAddress := "0xCBe7142F5c16755D8683BA329EFA1ABF7b54482d"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ETLT":
		fmt.Println("Selected Token: ETLT")
		tokenAddress := "0x54eFeC15D08428C7Ba31f8F085D4860EE6e38313"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DIS":
		fmt.Println("Selected Token: DIS")
		tokenAddress := "0x220b71671b649c03714da9c621285943f3cbcdc6"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SCA":
		fmt.Println("Selected Token: SCA")
		tokenAddress := "0x1FbD3dF007eB8A7477A1Eab2c63483dCc24EfFD6"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "MTS":
		fmt.Println("Selected Token: MTS")
		tokenAddress := "0xa9598333b99d14d90bc81cad8af82c4c70625e75"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "JEM":
		fmt.Println("Selected Token: JEM")
		tokenAddress := "0x21cf09BC065082478Dcc9ccB5fd215A978Dc8d86"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "VRGX":
		fmt.Println("Selected Token: VRGX")
		tokenAddress := "0x4861B1a0eAD261897174fD849cA0f5154fcF2442"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SAFEBTC":
		fmt.Println("Selected Token: SAFEBTC")
		tokenAddress := "0x62d693fE5C13b5A5b24C9ec3F423E51C35F5624F"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "IDALL":
		fmt.Println("Selected Token: IDALL")
		tokenAddress := "0xce80ce10fa806f4aa8755ab92cd268c51d7fd867"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BDT":
		fmt.Println("Selected Token: BDT")
		tokenAddress := "0x4Efe8665e564bF454cCF5C90Ee16817F7485d5Cf"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YLFI":
		fmt.Println("Selected Token: YLFI")
		tokenAddress := "0x186af393bf9ceef31ce7eae2b468c46231163cc7"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YFD":
		fmt.Println("Selected Token: YFD")
		tokenAddress := "0x4f4f0ef7978737ce928bff395529161b44e27ad9"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "UCAP":
		fmt.Println("Selected Token: UCAP")
		tokenAddress := "0xbaA70614C7AAfB568a93E62a98D55696bcc85DFE"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "AWX":
		fmt.Println("Selected Token: AWX")
		tokenAddress := "0xA51Fc71422a30FA7FFa605B360c3B283501b5bf6"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "VOICE":
		fmt.Println("Selected Token: VOICE")
		tokenAddress := "0x2e2364966267B5D7D2cE6CD9A9B5bD19d9C7C6A9"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "EPAY":
		fmt.Println("Selected Token: EPAY")
		tokenAddress := "0x2b5ca2f9510cf1e3595ff219f24d75d4244585ea"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "GIX":
		fmt.Println("Selected Token: GIX")
		tokenAddress := "0xbd434a09191d401da3283a5545bb3515d033b8c4"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "XPT":
		fmt.Println("Selected Token: XPT")
		tokenAddress := "0xf0814d0E47F2390a8082C4a1BD819FDDe50f9bFc"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SLINK":
		fmt.Println("Selected Token: SLINK")
		tokenAddress := "0x3de7148c41e3b3233f3310e794f68d8e70ca69af"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "UBIN":
		fmt.Println("Selected Token: UBIN")
		tokenAddress := "0xb9EcEb9F717852Ad0D936B46155cB0c0f43cBE8E"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "PICA":
		fmt.Println("Selected Token: PICA")
		tokenAddress := "0xA7E0719a65128b2f6cDbc86096753Ff7d5962106"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LST":
		fmt.Println("Selected Token: LST")
		tokenAddress := "0x355376d6471e09a4ffca8790f50da625630c5270"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BUND":
		fmt.Println("Selected Token: BUND")
		tokenAddress := "0x8D3E855f3f55109D473735aB76F753218400fe96"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "AXIA":
		fmt.Println("Selected Token: AXIA")
		tokenAddress := "0x793786e2dd4Cc492ed366a94B88a3Ff9ba5E7546"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "CAMP":
		fmt.Println("Selected Token: CAMP")
		tokenAddress := "0xE9E73E1aE76D17A16cC53E3e87a9a7dA78834d37"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "TWI":
		fmt.Println("Selected Token: TWI")
		tokenAddress := "0xdad26bce7dcf59cd03a2455558e4dd73e1c07b66"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "XCF":
		fmt.Println("Selected Token: XCF")
		tokenAddress := "0x010d14d36c3ea6570d240ae3ac9d660398f7c48e"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ZIN":
		fmt.Println("Selected Token: ZIN")
		tokenAddress := "0x033e223870f766644f7f7a4B7dc2E91573707d06"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "DESH":
		fmt.Println("Selected Token: DESH")
		tokenAddress := "0x95ba34760ac3d7fbe98ee8b2ab33b4f1a6d18878"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BUP":
		fmt.Println("Selected Token: BUP")
		tokenAddress := "0xB04DFdb8271ed2d5e13858562C44A77D3CEb9e57"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BTNYX":
		fmt.Println("Selected Token: BTNYX")
		tokenAddress := "0x8fb6c8a44a4e23fd1f5a936818b39083b4cdc865"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ETHV":
		fmt.Println("Selected Token: ETHV")
		tokenAddress := "0x5072a7580a9a83394acd3387609772ebaaa4ab60"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "NAZ":
		fmt.Println("Selected Token: NAZ")
		tokenAddress := "0x7723a1d7b939e0a49959363bf057ca57c7215e75"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YFICG":
		fmt.Println("Selected Token: YFICG")
		tokenAddress := "0x9080e92296a176883aAB1d7d1B7e50BC055B0cAa"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "TAT":
		fmt.Println("Selected Token: TAT")
		tokenAddress := "0x37Ee79E0B44866876de2fB7F416d0443DD5ae481"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YYFI":
		fmt.Println("Selected Token: YYFI")
		tokenAddress := "0xaF20b44C1C651D1d29cFB916eE2A0630B828Eb7A"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "YFIII":
		fmt.Println("Selected Token: YFIII")
		tokenAddress := "0x649eBF73043Ffcc70A59855ecd8a568FD996415a"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "FCD":
		fmt.Println("Selected Token: FCD")
		tokenAddress := "0x74db83feba1574fec860413eb509d1ddfb1b730b"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "BFI":
		fmt.Println("Selected Token: BFI")
		tokenAddress := "0x2b2b0559081c41e962777B5049632fdb30f7E652"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SUP8EME":
		fmt.Println("Selected Token: SUP8EME")
		tokenAddress := "0x47935Edfb3CDd358C50F6c0Add1Cc24662e30F5f"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "OBR":
		fmt.Println("Selected Token: OBR")
		tokenAddress := "0x595643d83b35df38e29058976c04000acfa31570"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "SWISS":
		fmt.Println("Selected Token: SWISS")
		tokenAddress := "0x692eb773e0b5b7a79efac5a015c8b36a2577f65c"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "TBP":
		fmt.Println("Selected Token: TBP")
		tokenAddress := "0x2bfAf3598Ee675aF548F2A772488bA5c8946C419"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "LELE":
		fmt.Println("Selected Token: LELE")
		tokenAddress := "0x1b6e4b5ad639efd5733f37f7af22fbe86718c5d8"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "ENOL":
		fmt.Println("Selected Token: ENOL")
		tokenAddress := "0x63D0eEa1D7C0d1e89d7e665708d7e8997C0a9eD6"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	case "STK":
		fmt.Println("Selected Token: STK")
		tokenAddress := "0x33c77ebbf799a46a3112ea3021b540afa4c3be27"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	default:
		fmt.Println("Selected Default Token: STK")
		tokenAddress := "0x33c77ebbf799a46a3112ea3021b540afa4c3be27"
		response, err := SendERC20s(tokenAddress, mnemonic, receiverAddress, inAmount, token);
		return response, err
	}
}
