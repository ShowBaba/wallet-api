# Crypto Wallet API built ontop of Wallet-core
&nbsp;

# Prerequisite 
1. Docker installation

&nbsp;
# Build process
1. ```git clone https://github.com/ShowBaba/wallet-api.git && cd wallet-api```
2. ```docker build . --tag wallet-api-dev```
3. ```docker run -p 8080:8080 -ti wallet-api-dev```
4. Application is now runing at `http://127.0.0.1:8080`


# REST API

&nbsp;
## Create a New Wallet

### Request

`GET /api/create/`

    curl -i -H 'Accept: application/json' http://127.0.0.1:8080/api/create/

### Response

    HTTP/1.1 201 Created
    Date: Thu, 24 Feb 2011 12:36:30 GMT
    Status: 201 Created
    Connection: close
    Content-Type: application/json

    {"payload":"hotel similar duck marine insane odor age knee collect tree eternal child","success":true}

&nbsp;
## Import Existing Wallet

### Request

`POST /api/import/`

    curl --header "Content-Type: application/json" \
    --request POST \
    --data '{"mnemonic": "pony tell swift announce guard witness echo border leisure work thumb fluid"}' \
    http://127.0.0.1:8080/api/import/

### Response

    HTTP/1.1 201 Created
    Date: Thu, 24 Feb 2011 12:36:30 GMT
    Status: 200 OK
    Connection: close
    Content-Type: application/json

    {"addresses":{"ADA":"addr1ssxey3kw3jukwe9h4xj2nuac6j7n288d7mt7c6cj79edry2aj6neza7fzxq09hk4gealh2hft6dmwjt9szswwmxnm97fwvn2qdrwhl79ac8604","AE":"ak_8HUtFrsb61Bx8qkUf5fqWiGYx79GnGfREv47D9hV444Cex2a2","AION":"0xa0ba696c3da0603f4625e6ab0a4f9a877b582cd66f1c0b1406e0aae10bdbe881","ALGO":"KLPMI7IXI2XMMFY4DICS4JWSQZOJMBNIKCRN42Q3WDMUMPBW2RZAYURPPM","ATOM":"cosmos1c2sjgg4xhy8jc9678vm7gc3dg996k2mvkjwyhy","BAND":"band10rqva3pcaeel2t2fvl7p7f25wy723ks7a4wvwk","BNB":"bnb1pjrgfyuc5d3y78cwr3vk8d4c3xtg7s8ntp9gmx","BNT":"bluzelle1pvykqdr25ukfhgrck5nk3u34m3d4sgjh54fa58","BTC":"bc1qrt05c37mgrmewj6zhrpuedf03dgltvjm9mtqz0","BTG":"btg1qm6nhgq59sa9qgzg9kgeczllxnhxy6fkcw3snht","CLO":"0x2bd6Ee06ABa1Aa6cAb06D3B05210400F8E6Bbb35" .......... },"message":"Wallet imported successfully","success":true}

&nbsp;
## Send ETH

### Request

`GET /send/eth/`

    curl --header "Content-Type: application/json" \
    --request POST \
    --data '{"mnemonic": "resist since sell vast sleep liberty story sudden control diamond brain wrestle",
    "receiverAddress": "0x65D4E4A40f970304c24216BD1C86977B45D6d090",
    "amount": "0.1"}' \
    http://127.0.0.1:8080/api/send/eth/

### Response

    HTTP/1.1 200 OK
    Date: Thu, 24 Feb 2011 12:36:30 GMT
    Status: 200 OK
    Connection: close
    Content-Type: application/json

    {"response":{"from":"0x7Cc21DAd3ED15807618bd5f387c811CC1df22783","to":"0x65D4E4A40f970304c24216BD1C86977B45D6d090","amount":"0.00001ETH","gasPrice":"","nonce":"13","hash":"0x931e9ca39eab9fedf9741f8bea91378a850159adc3e94f89411c17e0537f1ae7"}}
    
&nbsp;
## Transfer ERC20 Tokens

### Request

`GET /send/erc20/`

    curl --header "Content-Type: application/json" \
    --request POST \
    --data '{"mnemonic": "riot repair praise camera swim entry local setup arctic much bamboo creek",
    "receiverAddress": "0x7Cc21DAd3ED15807618bd5f387c811CC1df22783",
    "amount": "1000",
    "token": "STK"}' \
    http://127.0.0.1:8080/api/send/erc20/

### Response

    HTTP/1.1 200 OK
    Date: Thu, 24 Feb 2011 12:36:30 GMT
    Status: 200 OK
    Connection: close
    Content-Type: application/json

    {"response":{"from":"0x65D4E4A40f970304c24216BD1C86977B45D6d090","to":"0x7Cc21DAd3ED15807618bd5f387c811CC1df22783","amount":"1000STK","gasPrice":"","nonce":"31","hash":"0xd286db791d35703eeba4b61139cf65aa8d4ed2be8b4d0b67aacaa20db81a3ae0"}}}
    
    
&nbsp;
## Transfer BTC

### Request

`GET /send/erc20/`

     curl --header "Content-Type: application/json" \
    --request POST \
    --data '{"mnemonic": "riot repair praise camera swim entry local setup arctic much bamboo creek",
    "receiverAddress": "0x7Cc21DAd3ED15807618bd5f387c811CC1df22783",
    "amount": "200"}' \
    http://127.0.0.1:8080/api/send/btc
