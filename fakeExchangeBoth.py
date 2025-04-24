from flask import Flask, Response
from flask import request
import random
import json
import time
import base64
import hmac
import hashlib
import os
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)  # Set the logging level to DEBUG
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

DYNAMIC = True if os.getenv('DYNAMIC', 0) else False
SANDBOX = True if os.getenv('SANDBOX', 0) else False

random_sub_account_id = str(random.randint(4, 99999))

API_KEY = "aaa"
SECRET = "bbb"
CURRENT_VERSION = "1"
PAGE_CURSOR_MAX = 2
PAGE_SIZE_MAX_VALUE = 500
OFF_EXCHANGE_RSA_SECRET_PUB_KEY = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtug0j82+C1WCcqCPEzEm
sao1kH4gIDHewI06SsiB1aIdZ/v+I/PTRTYhKC0JVtsio+KeF/YDWI3c1RZrMa9/
7yOoQ8QNNG0U65q2//LoSz3He6E9/7b5V+BrQwvCHPOv4kp+un9bZ23BqvX+jgJQ
aKTvjEeBUW6fOh2oupRGH51teBcQpmgPFP1b26BGFSiGBdyB1OX6qYchIv5C/XW/
d3NoOUD96kEMEsDUKCvXwPp5gelqZQoaGZZatE5AllFdJJQKXU8DWDXTJMSyxIIY
rzx6S5RToDDK/Z7SKG4k8q1pd6pViNe88DJYV6kJdSgiYThl07sATWo+6Ev6nFSo
z69Jx+BWx5v2aLJfc6ghuN7j5dOBtex+tklHMw0s1XCiE14Pyi6px9dNNJApp6wM
LIDmMeKTZ65ar22q5ySgrNQHvVOy66zRZhfOu5fueSPa4C3CBoarCpiUIQTVNzf5
AA3qBKfunIUqHYNzdvPt/MwQErW1G9XPxGC+az0Cc4qEmICUSlYiFC1BLD6YKpjP
MsPkuj2d9MYfDUQktt1IKsWOTE6NNVzmYpbZkA7TD6hcqd7rV6Zf5TcK9vvEB1V5
F0jJYUdNXygdzKOwY/OlQ0eoF5vb6XU46y24cCnKgJ23ZfdLJJrFOdpbEaooErhn
37BWbAWH9EpcHM9pFNUYOhkCAwEAAQ==
-----END PUBLIC KEY-----
"""

OFF_EXCHANGE_RSA_PARTNER_SECRET_PRIVATE_KEY = """
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCaRq6Tustlzktq
4IQWWAp0oSLtSvvROXweVyhldRPS4b26NSWOB94aB+4E5rM0hqVNT038ca13Nb46
2MArLvimioTx++XRWhjHqqltc8amcJLX4rzMSVPQ+k+YHjw48Hs/BZkCtNTBRHds
px5wtAM3JvofQgYTknM2BGqNoxyhjEvRk7Wr92PK4J9OS02ISQePGgnrgmBbEoOX
8NsTLYJECW6xw1nbbkG/EdXIzx+J+y6fb0ZlJdoE/OvTXfUpHSMHqrFEXAauJ+Ip
czVYdG/2zv0DDmz7IQNKucXFXE70N5aI9VVNPtuY2/7f8TONysRloQAM+j8JWsew
XuZgDUKnAgMBAAECggEAd28g191UeYwrdqI5n9KoxYG5uFrEeEU4gYSYEXOB1VBN
wUpDuKD+oMhizAiN06wpbKBoj3ayBAfnLUd//e5vMP8rzOpmEJzfcjP81m866r9b
7yXpY32hFbeyxuEhXjNONovu2NmFm9mVWthGCJpTou7Z1DkY2y4VY0wn8V7FW4o9
o8ifEJeP8RtDAPKdQZn6FMMxWl0WRBkRFcNzg149ERCiJ7A48eXVdseuONfvVRuk
amvo/UkussW+x21zX/OEqMsuJA8/Ym2T2tBTTkbSvSSutBY8JuVkO4y4rRYLJFno
VvqQr34IXVN5bOTiXvmQjJwwywxEzzWbuyv7YKjkAQKBgQDKur6rU/VxtDb1LM8Y
CU0tf+KK/S6Eq6xaAPf4HTKtmmwfP8RGXnntkUXIM7+hPAtKSE810d+hhPV43SWR
NgumWsNPogi7DvHLOVVNNVZwa/10KLHudfFZBkunHrgpuawrb7criTCTZ5Tf8MHt
Iu6gliZe5068Ip5LD3X2zYofxwKBgQDC0JBndir0YtEfIUueGlsOYUD9xc7j1UP8
oMxv9vCTWquqEJ8+lo1wiGRy+oJVTsUOXvRfKVfr01JcNbHBnH09j9dcjUSBDsw3
/t6fZ7AeCe7xHS6jL9hWizobc/K8jEzeN6n7YAkoAQVzs179vU6zUfUxdXKYpBSC
hJ1rMHuGIQKBgDG2n6EV4p9yaPOwfExRo5pfvOcGdQzVqFsd17EBP/cwYgk7st7q
tg2azTjt77UTK1WY68uv3p4WI7fyyw6T6UFvCmwRuQBeBs8mDRP023CQGsQMYq2u
QHPrRkwCDXk17dFtAMbtSnsrMGfF+1gyc7/vchNdt4INHzIa5XuTJabrAoGAf9GF
nUxLvJKFMI6Q5YfXTGUE1jwNlTBc7gi2eZOknpmz3d4QDWmMHVRvy3yPPNd0tQwZ
+8HNfN3mwLc+DJDXHygcHg5V7vM9jFO9zwqh4+OSkUIbUlhW8dlhY5e8oHbRDE+r
SFHnUAbzg8khPwwQ8diJLk0nxfyJtGS8QBLMSOECgYByYck6Gic7O9E7Hg2IVs8r
i2+KDulWGWaH7rURz5/7O5uod+mdRMqto2ppfyskZiT3Fwi9ZYlJoVQ76CjyX0wV
ouZyDzoutFooF2t0cyUr/WkZQlnIfk14rliLoU2VQZ3+GdRFzmmty4v1h6jy/+3Y
dcjO6OcDo8KlkZ+1RLpIjg==
-----END PRIVATE KEY-----
"""

XLM_SYMBOL = "XLM_TEST" if SANDBOX else "XLM"
XRP_SYMBOL = "XRP_TEST" if SANDBOX else "XRP"
USDT_SYMBOL = "USDT_TEST3" if SANDBOX else "USDT"
USDC_SYMBOL = "USDC_ETH_TEST5_6ZNT" if SANDBOX else "USDC"
ETH_SYMBOL = "ETH_TEST5" if SANDBOX else "ETH_TEST5"
BTC_SYMBOL = "BTC_TEST" if SANDBOX else "BTC"
SOL_SYMBOL = "SOL_TEST" if SANDBOX else "SOL"

ETH_NETWORK = "ETH_TEST5"
USDC_NETWORK = "ETH_TEST5"  # ETH_NETWORK
# Using the newer model of network names, as a test.
SOL_NETWORK = "SOL_TEST" if SANDBOX else "Solana"
USDT_NETWORK = SOL_NETWORK

EXISTING_DEPOSIT_ADDRESSES = {
    ETH_SYMBOL: {
        "depositAddress": "0xb794f5ea0ba39494ce839613fffba74279579268",
        "depositAddressTag": "63163621"
    },
    "XLM_TEST": {
        "depositAddress": "GDKV3Y3T6U6TO6AWWRK5F75T7KCBJN7XXCW7WFK7MGRVCJ7MM6LUOBWC",
        "depositAddressTag": "2197583285"
    },
    XRP_SYMBOL: {
        "depositAddress": "rLNkYgVwDnXBBoprfMTyZv84QRTSkL9MXz",
        "depositAddressTag": "25878995"
    },
    "ALGO_TEST": {
        "depositAddress": "KRGV2OL7WEOL76PBJRB7GCJ7IYMDFZPMZOH2TONHXESC3ZIOCYU52UWYSY",
        "depositAddressTag": "0934507FB81E2F8C27D6"
    },

}

import random

BALANCES = [
    {
        "type": "EXCHANGE",
        "displayName": "Exchange Account",
        "balances": [
            {
                "coinSymbol": "XLM_TEST",
                "totalAmount": "195.172612",
                "pendingAmount": "188.2315812",
                "availableAmount": "100",
                "creditAmount": "500000"
            },
            {
                "coinSymbol": "USDC",
                "totalAmount": "100",
                "pendingAmount": "100",
                "availableAmount": "100",
                "creditAmount": "1234"
            },
            {
                "coinSymbol": XRP_SYMBOL,
                "totalAmount": "0",
                "pendingAmount": "0",
                "availableAmount": "0",
                "creditAmount": "100"
            },
            {
                "coinSymbol": ETH_SYMBOL,
                "totalAmount": "1",
                "pendingAmount": "0",
                "availableAmount": "1"
            }
        ]
    },
    {
        "type": "SPOT",
        "displayName": "Spot Account",
        "balances": [
            {
                "coinSymbol": ETH_SYMBOL,
                "totalAmount": "1231.11111",
                "pendingAmount": "441.2",
                "availableAmount": "22"
            },
            {
                "coinSymbol": "ALGO",
                "totalAmount": "5",
                "pendingAmount": "0",
                "availableAmount": "5",
                "creditAmount": "5"
            },
            {
                "coinSymbol": "USDT",
                "totalAmount": "5",
                "pendingAmount": "0",
                "availableAmount": "5",
                "creditAmount": "5"
            },
        ]
    },
    {
        "type": "MARGIN",
        "displayName": "Margin Account",
        "balances": [
            {
                "coinSymbol": "ALGO_TEST",
                "totalAmount": "1",
                "pendingAmount": "0",
                "availableAmount": "1"
            }
        ]
    }
]
'''
from flask import Flask, send_from_directory
# Define a route to serve files from the webroot directory
@app.route('/<path:filename>')
def serve_file(filename):
    return send_from_directory('', filename)
'''


def validateHeaders(headers):
    return all(["X-FBAPI-TIMESTAMP" in headers,
                "X-FBAPI-SIGNATURE" in headers,
                "X-FBAPI-NONCE" in headers,
                "X-FBAPI-KEY" in headers])


def validateAPIKeyHeader(headers):
    return headers["X-FBAPI-KEY"] == API_KEY


def validateTimestampHeader(headers):
    secondsEX = time.time()
    secondsFB = int(headers["X-FBAPI-TIMESTAMP"]) * 0.001

    # The difference between the timestamp and the API service time must be less than 60 seconds
    # or the request will be considered expired and rejected.
    return (secondsEX - secondsFB) < 60


def validateSignature(headers, method, endpoint, body):
    signaturePayload = headers["X-FBAPI-TIMESTAMP"] + headers["X-FBAPI-NONCE"] + method + endpoint.replace('/api',
                                                                                                           '') + body
    signature = base64.b64encode(hmac.new(SECRET.encode('utf-8'),
                                          signaturePayload.encode('utf-8'),
                                          hashlib.sha512).digest()).decode('utf-8')
    return signature == headers['X-FBAPI-SIGNATURE']


def validateOffExchangeSignature(headers, method, endpoint, body):
    app.logger.info(f'headers received: {headers}')
    if "X-OFF-EXCHANGE-NONCE" not in headers or \
            "X-OFF-EXCHANGE-TIMESTAMP" not in headers or \
            "X-OFF-EXCHANGE-SIGNATURE" not in headers:
        return True

    app.logger.info('All OFF-EXCHANGE  headers are present')
    if all(["X-OFF-EXCHANGE-NONCE" in headers,
            "X-OFF-EXCHANGE-TIMESTAMP" in headers,
            "X-OFF-EXCHANGE-SIGNATURE" in headers]):
        signaturePayload = headers["X-OFF-EXCHANGE-TIMESTAMP"] + headers[
            "X-OFF-EXCHANGE-NONCE"] + method + endpoint.replace('/api/v' + CURRENT_VERSION, '') + body
        app.logger.info(f'signature payload received: "{signaturePayload}"')

        public_key = serialization.load_pem_public_key(
            OFF_EXCHANGE_RSA_SECRET_PUB_KEY.encode('utf-8'),
            default_backend()
        )
        try:
            public_key.verify(base64.b64decode(headers['X-OFF-EXCHANGE-SIGNATURE']),
                              signaturePayload.encode('utf-8'),
                              asym_padding.PKCS1v15(),
                              hashes.SHA512())
            app.logger.info(f'validateOffExchangeSignature SUCCESS')
            return True
        except:
            app.logger.error(f'validateOffExchangeSignature FAILED!!!!!')

    #  if we are here, then at least one of the off exchange headers is missing
    return False


def toAddOffExchangeResponseHeader(headers):
    if all(["X-OFF-EXCHANGE-NONCE" in headers,
            "X-OFF-EXCHANGE-TIMESTAMP" in headers,
            "X-OFF-EXCHANGE-SIGNATURE" in headers]):
        return True
    return False


def addResponseHeaders(body, requestHeader, method, endpoint):
    # response = jsonify(body)
    # signaturePayload = requestHeader["OFF-EXCHANGE-TIMESTAMP"] + requestHeader["OFF-EXCHANGE-NONCE"] + method + endpoint.replace('/api/v' + CURRENT_VERSION, '') + response.data.decode('utf-8')
    # json.dumps(callback_data.data["body"],separators=(',', ':'))
    body_string = json.dumps(body, separators=(',', ':'))
    signaturePayload = requestHeader["X-OFF-EXCHANGE-TIMESTAMP"] + requestHeader[
        "X-OFF-EXCHANGE-NONCE"] + method + endpoint.replace('/api/v' + CURRENT_VERSION, '') + body_string
    private_key = serialization.load_pem_private_key(
        OFF_EXCHANGE_RSA_PARTNER_SECRET_PRIVATE_KEY.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    app.logger.info(f'RESPONSE signaturePayload: {signaturePayload}')
    signature = private_key.sign(
        signaturePayload.encode('utf-8'),
        asym_padding.PKCS1v15(),
        hashes.SHA512()
    )
    response = Response()
    response.data = body_string
    response.headers["X-OFF-EXCHANGE-SIGNATURE"] = base64.b64encode(signature).decode('utf-8')
    app.logger.info(f'calculated response.data: {response.data}')
    app.logger.info(f'calculated response.headers: {response.headers}')

    return response


nonce = None


def validateNonce(headers):
    '''global nonce
    if nonce is None:
        nonce = 0

    receivedNonce = int(headers["X-FBAPI-NONCE"])
    if receivedNonce > nonce:
        nonce = receivedNonce
        return True'''
    return True


GET_ACCOUNTS_ENDPOINT = '/api/v' + CURRENT_VERSION + '/accounts'
GET_ACCOUNTS_METHOD = 'GET'


@app.route(GET_ACCOUNTS_ENDPOINT, methods=[GET_ACCOUNTS_METHOD])
def accounts():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_ACCOUNTS_METHOD,
                               GET_ACCOUNTS_ENDPOINT,
                               ""):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    app.logger.info(BALANCES)
    return json.dumps({
        list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: BALANCES
    })


SUPPORTED_ASSETS_DATA = [
    {
        "coinSymbol": USDC_SYMBOL,
        "network": USDC_NETWORK,
        "coinClass": "TOKEN",
        "identifiers": ["0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"]
    },
    {
        "coinSymbol": ETH_SYMBOL,
        "network": ETH_NETWORK,
        "coinClass": "BASE"
    },
    {
        "coinSymbol": SOL_SYMBOL,
        "network": SOL_NETWORK,
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "XLM_TEST",
        "network": "XLM_TEST",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "SOL_TEST" if SANDBOX else "SOL",
        "network": "Solana",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "LTC_TEST" if SANDBOX else "LTC",
        "network": "Litecoin",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "XRP_TEST" if SANDBOX else "XRP",
        "network": "Ripple",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "ALGO_TEST",
        "network": "ALGO_TEST",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "ALGO",
        "network": "Algorand",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": "USDC",
        "network": "XLM",
        "coinClass": "TOKEN",
        "identifiers": ["GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", "USDC"]
    },
    {
        "coinSymbol": "USDC",
        "network": "XLM_TEST",
        "coinClass": "TOKEN",
        "identifiers": ["GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5", "USDC"]
    },
    {
        "coinSymbol": "BTC_TEST" if SANDBOX else "BTC",
        "network": "Bitcoin",
        "coinClass": "BASE"
    },
    {
        "coinSymbol": XRP_SYMBOL,
        "network": "Ripple",
        "coinClass": "BASE"
    }
]

#
GET_SUPPORTED_ASSETS_ENDPOINT = '/api/v' + CURRENT_VERSION + '/supportedAssets'
GET_SUPPORTED_ASSETS_METHOD = 'GET'


@app.route(GET_SUPPORTED_ASSETS_ENDPOINT, methods=[GET_SUPPORTED_ASSETS_METHOD])
def supportedAssets():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    # elif not validateAPIKeyHeader(request.headers):
    #    return json.dumps({
    #        "error": "X-FBAPI-KEY is invalid!"
    #    }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_SUPPORTED_ASSETS_METHOD,
                               GET_SUPPORTED_ASSETS_ENDPOINT,
                               ""):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    return json.dumps({
        list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: SUPPORTED_ASSETS_DATA
    })


SUPPORTED_ASSETS = list(set([asset["coinSymbol"] for asset in SUPPORTED_ASSETS_DATA]))
SUPPORTED_NETWORKS = list(set([asset["network"] for asset in SUPPORTED_ASSETS_DATA]))
SUPPORTED_ACCOUNT_TYPES = list(set([balanceAccountInfo["type"] for balanceAccountInfo in BALANCES]))

GET_DEPOSIT_ADDRESS_ENDPOINT = '/api/v' + CURRENT_VERSION + '/depositAddress'
GET_DEPOSIT_ADDRESS_METHOD = 'GET'


@app.route(GET_DEPOSIT_ADDRESS_ENDPOINT, methods=[GET_DEPOSIT_ADDRESS_METHOD])
def depostAddressGET():
    params = request.args
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_DEPOSIT_ADDRESS_METHOD,
                               GET_DEPOSIT_ADDRESS_ENDPOINT,
                               '?' + request.query_string.decode("utf-8")):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    if "coinSymbol" not in params.keys():
        return json.dumps({
            "error": "Required field coinSymbol doesn't exist"
        }), 500
    elif "network" not in params.keys():
        return json.dumps({
            "error": "Required field network doesn't exist"
        }), 500
    elif "accountType" not in params.keys():
        return json.dumps({
            "error": "Required field accountType doesn't exist"
        }), 500
    elif params["coinSymbol"] not in SUPPORTED_ASSETS:
        return json.dumps({
            "error": "Coin symbol " + params["coinSymbol"] + " not supported!"
        }), 400
    elif params["network"] not in SUPPORTED_NETWORKS:
        return json.dumps({
            "error": "Network " + params["network"] + " not supported!"
        }), 400
    elif params["coinSymbol"] in EXISTING_DEPOSIT_ADDRESSES.keys():
        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: EXISTING_DEPOSIT_ADDRESSES[
                params["coinSymbol"]]
        })
    else:
        # Not created yet, empty results.
        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                "depositAddress": ""
            }
        })


POST_DEPOSIT_ADDRESS_ENDPOINT = '/api/v' + CURRENT_VERSION + '/depositAddress'
POST_DEPOSIT_ADDRESS_METHOD = 'POST'


@app.route(POST_DEPOSIT_ADDRESS_ENDPOINT, methods=[POST_DEPOSIT_ADDRESS_METHOD])
def depostAddressPOST():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_DEPOSIT_ADDRESS_METHOD,
                               POST_DEPOSIT_ADDRESS_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    params = json.loads(request.data)
    if "coinSymbol" not in params.keys():
        return json.dumps({
            "error": "Required field coinSymbol doesn't exist"
        }), 500
    elif "network" not in params.keys():
        return json.dumps({
            "error": "Required field network doesn't exist"
        }), 500
    elif "accountType" not in params.keys():
        return json.dumps({
            "error": "Required field accountType doesn't exist"
        }), 500
    elif params["coinSymbol"] not in SUPPORTED_ASSETS:
        return json.dumps({
            "error": "Coin symbol " + params["coinSymbol"] + " not supported!"
        }), 400
    elif params["network"] not in SUPPORTED_NETWORKS:
        return json.dumps({
            "error": "Network " + params["network"] + " not supported!"
        }), 400
    elif params["coinSymbol"] in EXISTING_DEPOSIT_ADDRESSES.keys():
        return json.dumps({
            "error": "Deposit address for coinSymbol " + params["coinSymbol"] + " already exist!"
        }), 400
    else:
        # On SOL, we will return a "failure" case, as in no deposit address is available.
        if params["coinSymbol"] == SOL_SYMBOL:
            return json.dumps({
                list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                    "depositAddress": ""
                }
            })

        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                "depositAddress": "0xb794f5eafba39494ce839613fffba74279333368",
                "depositAddressTag": "123123123"
            }
        })


def getAccountTypeIndex(accountType):
    for id in range(len(BALANCES)):
        if BALANCES[id]["type"] == accountType:
            return id

    raise ValueError(accountType)


def removeBalanceFromAccountType(accountType, symbol, amount):
    for id in BALANCES[getAccountTypeIndex(accountType)]["balances"]:
        if id["coinSymbol"] == symbol:
            id["availableAmount"] = str(float(id["availableAmount"]) - float(amount))
            id["totalAmount"] = str(float(id["totalAmount"]) - float(amount))
            return


def addBalanceToAccountType(accountType, symbol, amount):
    accountTypeIndex = getAccountTypeIndex(accountType)
    for id in BALANCES[accountTypeIndex]["balances"]:
        if id["coinSymbol"] == symbol:
            id["availableAmount"] = str(float(id["availableAmount"]) + float(amount))
            id["totalAmount"] = str(float(id["totalAmount"]) + float(amount))
            return

    BALANCES[accountTypeIndex]["balances"].append({
        "coinSymbol": symbol,
        "totalAmount": amount,
        "pendingAmount": "0.0",
        "availableAmount": amount,
        "borrowedAmount": "0.0"
    })


def transferBalance(fromAccountType, toAccountType, symbol, amount):
    removeBalanceFromAccountType(fromAccountType, symbol, amount)
    addBalanceToAccountType(toAccountType, symbol, amount)


POST_INTERNAL_TRANSFER_ENDPOINT = '/api/v' + CURRENT_VERSION + '/internalTransfer'
POST_INTERNAL_TRANSFER_METHOD = 'POST'


@app.route(POST_INTERNAL_TRANSFER_ENDPOINT, methods=[POST_INTERNAL_TRANSFER_METHOD])
def internalTransfer():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_INTERNAL_TRANSFER_METHOD,
                               POST_INTERNAL_TRANSFER_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400

    params = json.loads(request.data)
    if "fromAccountType" not in params.keys():
        return json.dumps({
            "error": "Required field fromAccountType doesn't exist"
        }), 500
    elif "toAccountType" not in params.keys():
        return json.dumps({
            "error": "Required field toAccountType doesn't exist"
        }), 500
    elif "coinSymbol" not in params.keys():
        return json.dumps({
            "error": "Required field coinSymbol doesn't exist"
        }), 500
    elif "amount" not in params.keys():
        return json.dumps({
            "error": "Required field amount doesn't exist"
        }), 500
    elif params["fromAccountType"] not in SUPPORTED_ACCOUNT_TYPES:
        return json.dumps({
            "error": "(From) Account type " + params["fromAccountType"] + " not supported!"
        }), 400
    elif params["toAccountType"] not in SUPPORTED_ACCOUNT_TYPES:
        return json.dumps({
            "error": "(To) Account type " + params["toAccountType"] + " not supported!"
        }), 400
    elif params["coinSymbol"] not in SUPPORTED_ASSETS:
        return json.dumps({
            "error": "coinSymbol " + params["coinSymbol"] + " is not supported!"
        }), 400
    else:
        # On SOL, we will return a "failure" case, as in the rate limiter failed.
        if params["coinSymbol"] == SOL_SYMBOL:
            return json.dumps({
                "error": "Imitating rate limit failure for internal transfer (SOL)"
            }), 429
        # On SOL, we don't increment the nonce, as it is imitating a rate limit ban. So do it after if it isn't SOL.
        elif not validateNonce(request.headers):
            return json.dumps({
                "error": "X-FBAPI-NONCE is invalid!"
            }), 400
        else:
            if DYNAMIC:
                transferBalance(params["fromAccountType"],
                                params["toAccountType"],
                                params["coinSymbol"],
                                params["amount"])

            return json.dumps({
                list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                    "completed": True,
                    # Just to be a bit explicit
                    "transactionID": params["amount"] +
                                     params["coinSymbol"] + "from" +
                                     params["fromAccountType"] + "to" +
                                     params["toAccountType"]
                }
            })


POST_WITHDRAW_ENDPOINT = '/api/v' + CURRENT_VERSION + '/withdraw'
POST_WITHDRAW_METHOD = 'POST'


@app.route(POST_WITHDRAW_ENDPOINT, methods=[POST_WITHDRAW_METHOD])
def externalTransfer():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_WITHDRAW_METHOD,
                               POST_WITHDRAW_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400

    params = json.loads(request.data)
    if "accountType" not in params.keys():
        return json.dumps({
            "error": "Required field accountType doesn't exist"
        }), 500
    elif "toAddress" not in params.keys():
        return json.dumps({
            "error": "Required field toAddress doesn't exist"
        }), 500
    elif "coinSymbol" not in params.keys():
        return json.dumps({
            "error": "Required field coinSymbol doesn't exist"
        }), 500
    elif "amount" not in params.keys():
        return json.dumps({
            "error": "Required field amount doesn't exist"
        }), 500
    elif "network" not in params.keys():
        return json.dumps({
            "error": "Required field network doesn't exist"
        }), 500
    elif "isGross" not in params.keys():
        return json.dumps({
            "error": "Required field isGross doesn't exist"
        }), 500
    elif params["isGross"] not in ["true", "false"]:
        return json.dumps({
            "error": "isGross has an invalid value: " + params["isGross"]
        }), 500
    elif params["accountType"] not in SUPPORTED_ACCOUNT_TYPES:
        return json.dumps({
            "error": "(From) Account type " + params["accountType"] + " not supported!"
        }), 400
    elif params["coinSymbol"] not in SUPPORTED_ASSETS:
        return json.dumps({
            "error": "coinSymbol " + params["coinSymbol"] + " is not supported!"
        }), 400
    elif params["network"] not in SUPPORTED_NETWORKS:
        return json.dumps({
            "error": "network " + params["network"] + " is not supported!"
        }), 400
    else:
        # On SOL, we will return a "failure" case, as in the rate limiter failed.
        if params["coinSymbol"] == SOL_SYMBOL:
            return json.dumps({
                "error": "Imitating rate limit failure for external transfer (SOL)"
            }), 429
        # On SOL, we don't increment the nonce, as it is imitating a rate limit ban. So do it after if it isn't SOL.
        elif not validateNonce(request.headers):
            return json.dumps({
                "error": "X-FBAPI-NONCE is invalid!"
            }), 400
        else:
            return json.dumps({
                list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                    "transactionID": params["amount"] +
                                     params["coinSymbol"] +
                                     params["network"] + "from" +
                                     params["accountType"] + "to" +
                                     params["toAddress"]
                }
            })


GET_WITHDRAWAL_FEE_ENDPOINT = '/api/v' + CURRENT_VERSION + '/withdrawalFee'
GET_WITHDRAWAL_FEE_METHOD = 'GET'


@app.route(GET_WITHDRAWAL_FEE_ENDPOINT, methods=[GET_WITHDRAWAL_FEE_METHOD])
def withdrawalFee():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_WITHDRAWAL_FEE_METHOD,
                               GET_WITHDRAWAL_FEE_ENDPOINT,
                               '?' + request.query_string.decode("utf-8")):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    params = request.args
    if "transferAmount" not in params.keys():
        return json.dumps({
            "error": "Required field transferAmount doesn't exist"
        }), 500
    elif "coinSymbol" not in params.keys():
        return json.dumps({
            "error": "Required field coinSymbol doesn't exist"
        }), 500
    elif "network" not in params.keys():
        return json.dumps({
            "error": "Required field network doesn't exist"
        }), 500
    elif params["coinSymbol"] not in SUPPORTED_ASSETS:
        return json.dumps({
            "error": "coinSymbol " + params["coinSymbol"] + " is not supported!"
        }), 400
    elif params["network"] not in SUPPORTED_NETWORKS:
        return json.dumps({
            "error": "network " + params["network"] + " is not supported!"
        }), 400
    else:
        # Will return a constant value
        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                "feeAmount": "0.23823"
            }
        })


GET_TRANSACTION_BY_ID = '/api/v' + CURRENT_VERSION + '/transactionByID'
GET_TRANSACTION_BY_ID_METHOD = 'GET'


@app.route(GET_TRANSACTION_BY_ID, methods=[GET_TRANSACTION_BY_ID_METHOD])
def transactionByIDGET():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_TRANSACTION_BY_ID_METHOD,
                               GET_TRANSACTION_BY_ID,
                               '?' + request.query_string.decode("utf-8")):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400
    # # TO REMOVE
    # return json.dumps({"error": "Rate Limit"}), 429

    params = request.args
    if "transactionID" not in params.keys():
        return json.dumps({
            "error": "Required field transactionID doesn't exist"
        }), 500
    else:
        # TransactionID that start with 0x0 will always fail.
        if params["transactionID"].lower().startswith("0x0"):
            return json.dumps({
                list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                    "status": "NOT_FOUND",
                }
            })

        if DYNAMIC:
            removeBalanceFromAccountType("EXCHANGE", ETH_SYMBOL, "1.1")

        # By default, the transactions are crypto
        status = "COMPLETED"
        # status = "PENDING_MANUAL_APPROVAL"
        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                "transactionID": params["transactionID"],
                "status": status,
                "txHash": "0x44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf" if status == "COMPLETED" else "",
                "amount": "1.1",
                "serviceFee": "0.000000031",
                "coinSymbol": ETH_SYMBOL,
                "network": ETH_NETWORK,
                "direction": "CRYPTO_WITHDRAWAL",
                "timestamp": 1546658861000
            }
        })


GET_TRANSACTION_BY_HASH_ENDPOINT = '/api/v' + CURRENT_VERSION + '/transactionByHash'
GET_TRANSACTION_BY_HASH_METHOD = 'GET'


@app.route(GET_TRANSACTION_BY_HASH_ENDPOINT, methods=[GET_TRANSACTION_BY_HASH_METHOD])
def transactionByHashGET():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_TRANSACTION_BY_HASH_METHOD,
                               GET_TRANSACTION_BY_HASH_ENDPOINT,
                               '?' + request.query_string.decode("utf-8")):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    params = request.args
    if "txHash" not in params.keys():
        return json.dumps({
            "error": "Required field txHash doesn't exist"
        }), 500
    elif "network" not in params.keys():
        return json.dumps({
            "error": "Required field network doesn't exist"
        }), 500
    elif params["network"] not in SUPPORTED_NETWORKS:
        return json.dumps({
            "error": "network " + params["network"] + " is not supported!"
        }), 400
    else:
        # TxHash that start with 0x0 will always fail.
        if params["txHash"].lower().startswith("0x0"):
            return json.dumps({
                list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                    "status": "NOT_FOUND",
                }
            })

        if DYNAMIC:
            addBalanceToAccountType("EXCHANGE", ETH_SYMBOL, "1.1")

        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: {
                "transactionID": "0xa1b5c50284dbf475a9fb5c8dae1c04d19",
                "status": "COMPLETED",
                "txHash": params["txHash"],
                "amount": "1.1",
                "serviceFee": "0.000000031",
                "coinSymbol": ETH_SYMBOL,
                "network": params["network"],
                "direction": "CRYPTO_DEPOSIT",
                "timestamp": 1546658861000
            }
        })


def createFakeTransactionHistory(params):
    txHistoryList = []

    pageCursor = ""
    pageCursorIndex = 0
    if "pageCursor" in params:
        pageCursor = params["pageCursor"]
        pageCursorIndex = int(pageCursor) + 1

    txHashConstant = "44e25bc0ed840f9bf0e58d6227db15192d5b89e79ba4304da16b09703f68ceaf"
    externalTxIdConstant = "a1b5c50284dbf475a9fb5c8dae1c04d190"
    createdConstant = 1546658861000
    for x in range(int(params["pageSize"])):
        txObj = {}

        # We can find a transaction by knowing the page cursor.
        txObj["status"] = "PENDING_MANUAL_APPROVAL"  # "COMPLETED"
        txObj["amount"] = "11.5"
        txObj["serviceFee"] = "0.111"
        txObj["coinSymbol"] = params['coinSymbol']
        txObj["network"] = params["network"]
        txObj["txHash"] = (pageCursor + txHashConstant + str(x)) if txObj["status"] == "COMPLETED" else ""
        txObj["direction"] = "CRYPTO_DEPOSIT" if (x % 2 == 0) else "CRYPTO_WITHDRAWAL"

        if "WITHDRAWAL" in txObj["direction"]:
            txObj["transactionID"] = "0x" + pageCursor + externalTxIdConstant + str(x)
        else:
            txObj["transactionID"] = ""

        # Timestamp is an increasing amount, +1 for each entry, multiples of pageSize for each page.
        txObj["timestamp"] = createdConstant + (int(params['pageSize']) * pageCursorIndex) + x

        txHistoryList.append(txObj)

    return txHistoryList


GET_TX_HISTORY_ENDPOINT = '/api/v' + CURRENT_VERSION + '/transactionHistory'
GET_TX_HISTORY_METHOD = 'GET'


@app.route(GET_TX_HISTORY_ENDPOINT, methods=[GET_TX_HISTORY_METHOD])
def transactionHistory():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_TX_HISTORY_METHOD,
                               GET_TX_HISTORY_ENDPOINT,
                               '?' + request.query_string.decode("utf-8")):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    params = request.args
    if "fromDate" not in params.keys():
        return json.dumps({
            "error": "Required field fromDate doesn't exist"
        }), 500
    elif "toDate" not in params.keys():
        return json.dumps({
            "error": "Required field toDate doesn't exist"
        }), 500
    elif "pageSize" not in params.keys():
        return json.dumps({
            "error": "Required field pageSize doesn't exist"
        }), 500
    elif int(params["pageSize"]) <= 0 or int(params["pageSize"]) > PAGE_SIZE_MAX_VALUE:
        return json.dumps({
            "error": "pageSize has an invalid value: " + params["pageSize"]
        }), 500
    elif "isSubTransfer" not in params.keys():
        return json.dumps({
            "error": "Required field isSubTransfer doesn't exist"
        }), 500
    elif params["isSubTransfer"] not in ["true", "false"]:
        return json.dumps({
            "error": "isSubTransfer has an invalid value: " + params["isSubTransfer"]
        }), 500
    elif "coinSymbol" not in params.keys():
        return json.dumps({
            "error": "Required field coinSymbol doesn't exist"
        }), 500
    elif "network" not in params.keys():
        return json.dumps({
            "error": "Required field network doesn't exist"
        }), 500
    elif params["coinSymbol"] not in SUPPORTED_ASSETS:
        return json.dumps({
            "error": "coinSymbol " + params["coinSymbol"] + " is not supported!"
        }), 400
    elif params["network"] not in SUPPORTED_NETWORKS:
        return json.dumps({
            "error": "network " + params["network"] + " is not supported!"
        }), 400
    else:
        # SOL assets will always return empty.
        if params["coinSymbol"] == SOL_SYMBOL:
            return json.dumps({
                list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: []
            })

        data = {}
        data["transactions"] = createFakeTransactionHistory(params)

        # Increasing until PAGE_CURSOR_MAX
        if "pageCursor" in params:
            if int(params["pageCursor"]) < PAGE_CURSOR_MAX:
                data["nextPageCursor"] = str(int(params["pageCursor"]) + 1)
        else:
            data["nextPageCursor"] = "0"

        return json.dumps({
            list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: data
        })


COLLATERAL_VERSION = "1"
COLLATERAL_BASE_URL = '/api/v' + CURRENT_VERSION + '/collateral/v' + COLLATERAL_VERSION

POST_COLLATERAL_INITIATE_ENDPOINT = COLLATERAL_BASE_URL + '/initiate'
POST_COLLATERAL_INITIATE_METHOD = 'POST'

POST_COLLATERAL_ADDRESS_ENDPOINT = COLLATERAL_BASE_URL + '/address'
POST_COLLATERAL_ADDRESS_METHOD = 'POST'

POST_COLLATERAL_WITHDRAW_ENDPOINT = COLLATERAL_BASE_URL + '/withdraw'
POST_COLLATERAL_WITHDRAW_METHOD = 'POST'

GET_COLLATERAL_SETTLEMENT_ENDPOINT = COLLATERAL_BASE_URL + '/settlement'
GET_COLLATERAL_SETTLEMENT_METHOD = 'GET'

POST_COLLATERAL_SETTLEMENT_ENDPOINT = COLLATERAL_BASE_URL + '/settlement'
POST_COLLATERAL_SETTLEMENT_METHOD = 'POST'

POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT = COLLATERAL_BASE_URL + '/settlement/force'
POST_COLLATERAL_ENFORCE_SETTLEMENT_METHOD = 'POST'

POST_COLLATERAL_RESPONSE_ENDPOINT = COLLATERAL_BASE_URL + '/response'
POST_COLLATERAL_RESPONSE_METHOD = 'POST'

POST_COLLATERAL_NOTIFICATION = '/collateral/v' + COLLATERAL_VERSION + '/notify'
POST_COLLATERAL_NOTIFICATION_METHOD = 'POST'

POST_POLINA_DEBUG = '/polina'
POST_POLINA_DEBUG_METHOD = 'POST'

POST_COLLATERAL_ADD_ENDPOINT = COLLATERAL_BASE_URL + '/add'
POST_COLLATERAL_ADD_METHOD = 'POST'

NLV2_BASE_URL = '/api/v2'

GET_CAPABILITIES_ENDPOINT = f'{NLV2_BASE_URL}/capabilities'
GET_CAPABILITIES_METHOD = 'GET'

GET_CAPABILITIES_ASSETS_ENDPOINT = f'{GET_CAPABILITIES_ENDPOINT}/assets'
GET_CAPABILITIES_ASSETS_METHOD = 'GET'

GET_CAPABILITIES_ASSETS_ID_ENDPOINT = f'{GET_CAPABILITIES_ASSETS_ENDPOINT}/<id>'
GET_CAPABILITIES_ASSETS_ID_METHOD = 'GET'

GET_CAPABILITIES_LIQUIDITY_QUOTES_ENDPOINT = f'{GET_CAPABILITIES_ENDPOINT}/liquidity/quotes'
GET_CAPABILITIES_LIQUIDITY_QUOTES_METHOD = 'GET'

GET_CAPABILITIES_TRADING_BOOKS_ENDPOINT = f'{GET_CAPABILITIES_ENDPOINT}/trading/books'
GET_CAPABILITIES_TRADING_BOOKS_METHOD = 'GET'

# Use sub_account endpoint for account-specific URLs
GET_SUB_ACCOUNTS_ENDPOINT = f'{NLV2_BASE_URL}/accounts'
GET_ACCOUNTS_METHOD = 'GET'

GET_SUB_ACCOUNT_ENDPOINT = f'{GET_SUB_ACCOUNTS_ENDPOINT}/<accountId>'
GET_SUB_ACCOUNT_ENDPOINT2 = f'{GET_SUB_ACCOUNTS_ENDPOINT}/<accountId>'
GET_SUB_ACCOUNT_ENDPOINT3 = f'{GET_SUB_ACCOUNTS_ENDPOINT}/<accountId>'
GET_SUB_ACCOUNT_METHOD = 'GET'

GET_BALANCES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/balances'
GET_BALANCES_METHOD = 'GET'

GET_HISTORIC_BALANCES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/historic-balances'
GET_HISTORIC_BALANCES_METHOD = 'GET'

GET_LIQUIDITY_QUOTES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/liquidity/quotes'
GET_LIQUIDITY_QUOTES_METHOD = 'GET'

POST_LIQUIDITY_QUOTES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/liquidity/quotes'
POST_LIQUIDITY_QUOTES_METHOD = 'POST'

GET_LIQUIDITY_QUOTES_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/liquidity/quotes/<id>'
GET_LIQUIDITY_QUOTES_ID_METHOD = 'GET'

POST_LIQUIDITY_QUOTES_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/liquidity/quotes/<id>/execute'
POST_LIQUIDITY_QUOTES_ID_METHOD = 'POST'

GET_WITHDRAWAL_METHODS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/capabilities/transfers/withdrawals'
GET_WITHDRAWAL_METHODS_METHOD = 'GET'

GET_DEPOSIT_METHODS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/capabilities/transfers/deposits'
GET_DEPOSIT_METHODS_METHOD = 'GET'

POST_TRANSFER_WITHDRAWALS_BLOCKCHAIN_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/blockchain'
POST_TRANSFER_WITHDRAWALS_BLOCKCHAIN_METHOD = 'POST'

GET_TRANSFER_WITHDRAWALS_BLOCKCHAIN_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/blockchain'
GET_TRANSFER_WITHDRAWALS_BLOCKCHAIN_METHOD = 'GET'

POST_TRANSFER_WITHDRAWALS_FIAT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/fiat'
POST_TRANSFER_WITHDRAWALS_FIAT_METHOD = 'POST'

GET_TRANSFER_WITHDRAWALS_FIAT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/fiat'
GET_TRANSFER_WITHDRAWALS_FIAT_METHOD = 'GET'

POST_TRANSFER_WITHDRAWALS_PEERACCOUNT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/peeraccount'
POST_TRANSFER_WITHDRAWALS_PEERACCOUNT_METHOD = 'POST'

GET_TRANSFER_WITHDRAWALS_PEERACCOUNT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/peeraccount'
GET_TRANSFER_WITHDRAWALS_PEERACCOUNT_METHOD = 'GET'

POST_TRANSFER_WITHDRAWALS_SUBACCOUNT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/subaccount'
POST_TRANSFER_WITHDRAWALS_SUBACCOUNT_METHOD = 'POST'

GET_TRANSFER_WITHDRAWALS_SUBACCOUNT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/subaccount'
GET_TRANSFER_WITHDRAWALS_SUBACCOUNT_METHOD = 'GET'

GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals'
GET_ACCOUNT_TRANSFERS_WITHDRAWALS_METHOD = 'GET'

GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/withdrawals/<id>'
GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_METHOD = 'GET'

GET_ACCOUNT_TRANSFERS_DEPOSITS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/deposits'
GET_ACCOUNT_TRANSFERS_DEPOSITS_METHOD = 'GET'

GET_ACCOUNT_TRANSFERS_DEPOSITS_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/deposits/<id>'
GET_ACCOUNT_TRANSFERS_DEPOSITS_ID_METHOD = 'GET'

POST_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/deposits/addresses'
POST_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_METHOD = 'POST'

GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/deposits/addresses'
GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_METHOD = 'GET'

GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/deposits/addresses/<id>'
GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_METHOD = 'GET'

DELETE_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/transfers/deposits/addresses/<id>'
DELETE_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_METHOD = 'DELETE'

POST_ACCOUNT_COLLATERAL_LINK_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/link'
POST_ACCOUNT_COLLATERAL_LINK_METHOD = 'POST'

GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/link'
GET_ACCOUNT_COLLATERAL_LINK_METHOD = 'GET'

POST_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/addresses'
POST_ACCOUNT_COLLATERAL_ID_ADDRESSES_METHOD = 'POST'

GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/addresses'
GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_METHOD = 'GET'

GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/addresses/<id>'
GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_METHOD = 'GET'

POST_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/deposits'
POST_ACCOUNT_COLLATERAL_ID_DEPOSITS_METHOD = 'POST'

POST_ACCOUNT_COLLATERAL_ID_INTENT_DEPOSITS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/intents/deposits'
POST_ACCOUNT_COLLATERAL_ID_INTENT_DEPOSITS_METHOD = 'POST'

GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/deposits'
GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_METHOD = 'GET'

GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_COLLATERALTXID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/deposits/<collateralTxId>'
GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_COLLATERALTXID_METHOD = 'GET'

POST_ACCOUNT_COLLATERAL_ID_INTENT_WITHDRAWALS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/intents/withdrawals'
POST_ACCOUNT_COLLATERAL_ID_INTENT_WITHDRAWALS_METHOD = 'POST'

POST_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/withdrawals'
POST_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_METHOD = 'POST'

GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/withdrawals'
GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_METHOD = 'GET'

GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/withdrawals/<collateralTxId>'
GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_METHOD = 'GET'

POST_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/settlement'
POST_ACCOUNT_COLLATERAL_ID_SETTLEMENT_METHOD = 'POST'

GET_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/settlement'
GET_ACCOUNT_COLLATERAL_ID_SETTLEMENT_METHOD = 'GET'

GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/collateral/<collateralId>/settlements/<settlementVersion>'
GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_METHOD = 'GET'

GET_TRADING_BOOKS_ENDPOINT = f'{NLV2_BASE_URL}/trading/books'
GET_TRADING_BOOKS_METHOD = 'GET'

GET_TRADING_BOOKS_ID_ENDPOINT = f'{GET_TRADING_BOOKS_ENDPOINT}/<id>'
GET_TRADING_BOOKS_ID_METHOD = 'GET'

GET_TRADING_BOOKS_ID_ASKS_ENDPOINT = f'{GET_TRADING_BOOKS_ID_ENDPOINT}/asks'
GET_TRADING_BOOKS_ID_ASKS_METHOD = 'GET'

GET_TRADING_BOOKS_ID_BIDS_ENDPOINT = f'{GET_TRADING_BOOKS_ID_ENDPOINT}/bids'
GET_TRADING_BOOKS_ID_BIDS_METHOD = 'GET'

GET_TRADING_BOOKS_ID_HISTORY_ENDPOINT = f'{GET_TRADING_BOOKS_ID_ENDPOINT}/history'
GET_TRADING_BOOKS_ID_HISTORY_METHOD = 'GET'

GET_ACCOUNT_TRADING_ORDERS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/trading/orders'
GET_ACCOUNT_TRADING_ORDERS_METHOD = 'GET'

POST_ACCOUNT_TRADING_ORDERS_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/trading/orders'
POST_ACCOUNT_TRADING_ORDERS_METHOD = 'POST'

GET_ACCOUNT_TRADING_ORDERS_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/trading/orders/<id>'
GET_ACCOUNT_TRADING_ORDERS_ID_METHOD = 'GET'

DELETE_ACCOUNT_TRADING_ORDERS_ID_ENDPOINT = f'{GET_SUB_ACCOUNT_ENDPOINT}/trading/orders/<id>'
DELETE_ACCOUNT_TRADING_ORDERS_ID_METHOD = 'DELETE'

COLLATERAL_RESPONSES = {
    POST_COLLATERAL_INITIATE_ENDPOINT: {
        "status": True
    },
    POST_COLLATERAL_ADDRESS_ENDPOINT: {
        "received": True
    },
    POST_COLLATERAL_ADD_ENDPOINT: {
        "approved": True,
        "rejectionReason": "CVA amount is too small"
    },
    POST_COLLATERAL_WITHDRAW_ENDPOINT: {
        "approved": True
    },
    POST_COLLATERAL_SETTLEMENT_ENDPOINT: {
        "to_exchange": [
            {
                "fireblocksAssetId": "ALGO_TEST",
                "amount": "1",
                "destinationAddress": "KRGV2OL7WEOL76PBJRB7GCJ7IYMDFZPMZOH2TONHXESC3ZIOCYU52UWYSY",
                "destinationTag": "0934507FB81E2F8C27D6"
            }
        ],
        "to_collateral": [
            {
                "fireblocksAssetId": "ALGO_TEST",
                "amount": "1"
            }
        ]
    },
    POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT: {
        "approved": True
    },
    GET_CAPABILITIES_ENDPOINT: {
        "version": "1.0.37",
        "components": {
            "accounts": "*",
            "balances": "*",
            "transfers": "*",
            "transfersBlockchain": "*",
            "collateral": "*"
        }
    },
    GET_CAPABILITIES_ASSETS_ENDPOINT: {
        "assets": [
            {
                "id": "360de0ad-9ba1-45d5-8074-22453f193d65",
                "type": "Erc20Token",
                "blockchain": "Ethereum",
                "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "name": "USDC",
                "symbol": "USDC",
                "description": "USDC is a fully collateralized US Dollar stablecoin developed by CENTRE, the open source project with Circle being the first of several forthcoming issuers.",
                "decimalPlaces": 6
            },
            {
                "id": "606bce6b-ff15-4704-9390-b9e32a6cfcff",
                "type": "Erc20Token",
                "blockchain": "Polygon PoS",
                "contractAddress": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
                "name": "USDC",
                "symbol": "USDC",
                "description": "USD Coin is an ERC-20 stablecoin brought to you by Circle and Coinbase. It is issued by regulated and licensed financial institutions that maintain full reserves of the equivalent fiat currency.",
                "decimalPlaces": 6
            },
            {
                "id": "4386cf4d-83b2-4410-96da-0d3919a45506",
                "type": "StellarToken",
                "blockchain": "Stellar",
                "issuerAddress": "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
                "stellarCurrencyCode": "USDC",
                "name": "USDC",
                "symbol": "USDC",
                "description": "USDC is a fully collateralized US Dollar stablecoin, based on the open source fiat stablecoin framework developed by Centre.",
                "decimalPlaces": 2
            }
        ]
    },
    GET_CAPABILITIES_ASSETS_ID_ENDPOINT: {
        "id": "1",
        "name": "Ethereun Oz Coin",
        "symbol": "Oz",
        "description": "asset test",
        "decimalPlaces": 0,
        "testAsset": True,
        "type": "BucketAsset"
    },
    GET_CAPABILITIES_LIQUIDITY_QUOTES_ENDPOINT: {
        "capabilities": [
            {
                "id": "1",
                "fromAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "toAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                }
            }
        ]
    },
    GET_CAPABILITIES_TRADING_BOOKS_ENDPOINT: {
        "books": [
            {
                "id": "BTC/USDC",
                "description": "Bitcoin book",
                "baseAsset": {
                    "blockchain": "Bitcoin",
                    "cryptocurrencySymbol": "BTC"
                },
                "quoteAsset": {
                    "assetId": "f0844d82-7097-4521-95bc-d843724a893e"
                }
            },
            {
                "id": "GBP/USDC",
                "baseAsset": {
                    "nationalCurrencyCode": "GBP"
                },
                "quoteAsset": {
                    "assetId": "f0844d82-7097-4521-95bc-d843724a893e"
                }
            }
        ]
    },
    GET_SUB_ACCOUNTS_ENDPOINT: {
        "accounts": [
            {
                "id": random_sub_account_id,
                "title": "res test",
                "description": "res test",
                "balances": [
                    {
                        "id": "1",
                        "asset": {
                            "nationalCurrencyCode": "ADP",
                            "testAsset": True
                        },
                        "availableAmount": "10",
                        "lockedAmount": "1"
                    },
                    {
                        "id": "dc662581-42d3-4128-8454-3ce4bdb44329",
                        "asset": {
                            "cryptocurrencySymbol": "ETH",
                            "testAsset": True
                        },
                        "availableAmount": "54604.0132",
                        "lockedAmount": "1"
                    },
                    {
                        "id": "5cfed176-b745-4759-9611-6b0b699f1422",
                        "asset": {
                            "cryptocurrencySymbol": "ALGO",
                            "testAsset": True
                        },
                        "availableAmount": "795.608",
                        "lockedAmount": "1"
                    },
                ],
                "status": "active"
            },
            {
                "id": "2",
                "title": "res test sub",
                "description": "res test sub",
                "balances": [
                    {
                        "id": "1",
                        "asset": {
                            "nationalCurrencyCode": "ADP",
                            "testAsset": True
                        },
                        "availableAmount": "10",
                        "lockedAmount": "1"
                    },
                    {
                        "id": "dc662581-42d3-4128-8454-3ce4bdb44329",
                        "asset": {
                            "cryptocurrencySymbol": "ETH",
                            "testAsset": True
                        },
                        "availableAmount": "54604.0132",
                        "lockedAmount": "1"
                    },
                    {
                        "id": "5cfed176-b745-4759-9611-6b0b699f1422",
                        "asset": {
                            "cryptocurrencySymbol": "ALGO",
                            "testAsset": True
                        },
                        "availableAmount": "795.608",
                        "lockedAmount": "1"
                    },
                ],
                "status": "active",
                "parentId": "1"
            },
            {
                "id": "3",
                "title": "res test sub 2",
                "description": "res test sub",
                "balances": [
                    {
                        "id": "1",
                        "asset": {
                            "nationalCurrencyCode": "ADP",
                            "testAsset": True
                        },
                        "availableAmount": "10",
                        "lockedAmount": "1"
                    },
                    {
                        "id": "dc662581-42d3-4128-8454-3ce4bdb44329",
                        "asset": {
                            "cryptocurrencySymbol": "ETH",
                            "testAsset": True
                        },
                        "availableAmount": "54604.0132",
                        "lockedAmount": "1"
                    },
                    {
                        "id": "5cfed176-b745-4759-9611-6b0b699f1422",
                        "asset": {
                            "cryptocurrencySymbol": "ALGO",
                            "testAsset": True
                        },
                        "availableAmount": "795.608",
                        "lockedAmount": "1"
                    },
                ],
                "status": "active",
                "parentId": "1"
            }
        ]
    },
    GET_SUB_ACCOUNT_ENDPOINT: {
        "id": random_sub_account_id,
        "title": "res test",
        "description": "res test",
        "balances": [
            {
                "id": 1,
                "asset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "availableAmount": "10",
                "lockedAmount": "1"
            },
            {
                "id": "dc662581-42d3-4128-8454-3ce4bdb44329",
                "asset": {
                    "cryptocurrencySymbol": "ETH",
                    "testAsset": True
                },
                "availableAmount": "54604.0132",
                "lockedAmount": "1"
            },
            {
                "id": "5cfed176-b745-4759-9711-6b0b699f1422",
                "asset": {
                    "cryptocurrencySymbol": "BTC",
                    "testAsset": True
                },
                "availableAmount": "795.608",
                "lockedAmount": "1"
            },
            {
                "id": "5cfed176-b745-4759-9611-6b0b699f1422",
                "asset": {
                    "cryptocurrencySymbol": "ALGO",
                    "testAsset": True
                },
                "availableAmount": "795.608",
                "lockedAmount": "1"
            },
        ],
        "status": "active",
    },
    GET_BALANCES_ENDPOINT: {
        "balances": [
            {
                "id": "4ff63424-7e09-4cdf-b7f1-da7b7c65eabe",
                "asset": {
                    "nationalCurrencyCode": "USD"
                },
                "availableAmount": "1743.43",
                "lockedAmount": "0"
            }
        ]
    },
    GET_HISTORIC_BALANCES_ENDPOINT: {
        "balances": [
            {
                "id": "1",
                "asset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "availableAmount": "10",
                "lockedAmount": "1"
            }
        ]
    },
    GET_LIQUIDITY_QUOTES_ENDPOINT: {
        "quotes": [
            {
                "id": "1",
                "fromAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "fromAmount": "2",
                "toAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "toAmount": "2",
                "conversionFeeBps": 0,
                "status": "ready",
                "createdAt": "2019-08-24T14:15:22Z",
                "expiresAt": "2019-08-24T14:15:22Z"
            }
        ]
    },
    POST_LIQUIDITY_QUOTES_ENDPOINT: {
        "id": "1",
        "fromAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "fromAmount": "2",
        "toAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "toAmount": "2",
        "conversionFeeBps": 0,
        "status": "ready",
        "createdAt": "2019-08-24T14:15:22Z",
        "expiresAt": "2019-08-24T14:15:22Z"
    },
    GET_LIQUIDITY_QUOTES_ID_ENDPOINT: {
        "id": "1",
        "fromAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "fromAmount": "2",
        "toAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "toAmount": "2",
        "conversionFeeBps": 0,
        "status": "ready",
        "createdAt": "2019-08-24T14:15:22Z",
        "expiresAt": "2019-08-24T14:15:22Z"
    },
    POST_LIQUIDITY_QUOTES_ID_ENDPOINT: {
        "id": "1",
        "fromAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "fromAmount": "2",
        "toAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "toAmount": "2",
        "conversionFeeBps": 0,
        "status": "ready",
        "createdAt": "2019-08-24T14:15:22Z",
        "expiresAt": "2019-08-24T14:15:22Z"
    },
    GET_WITHDRAWAL_METHODS_ENDPOINT: {
        "capabilities": [
            {
                "id": "4bb2faf1-0220-49d1-9f57-e4fa23400ed4",
                "withdrawal": {
                    "asset": {
                        "blockchain": "Ethereum",
                        "cryptocurrencySymbol": "ETH",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain"
                },
                "balanceAsset": {
                    "blockchain": "Ethereum",
                    "cryptocurrencySymbol": "ETH",
                    "testAsset": True
                },
                "minWithdrawalAmount": "1"
            },
            {
                "id": "fc12f99d-c8a9-464b-941a-0dfa0c7b629c",
                "withdrawal": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain"
                },
                "balanceAsset": {
                    "blockchain": "Algorand",
                    "cryptocurrencySymbol": "ALGO",
                    "testAsset": True
                },
                "minWithdrawalAmount": "1"
            }
        ]
    },
    GET_DEPOSIT_METHODS_ENDPOINT: {
        "capabilities": [
            {
                "id": "4bb2faf1-0220-49d1-9f57-e4fa23400ed4",
                "deposit": {
                    "asset": {
                        "blockchain": "Ethereum",
                        "cryptocurrencySymbol": "ETH",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain"
                },
                "balanceAsset": {
                    "blockchain": "Ethereum",
                    "cryptocurrencySymbol": "ETH",
                    "testAsset": True
                },
                "addressCreationPolicy": "CanCreate"
            },
            {
                "id": "fc12f99d-c8a9-464b-941a-0dfa0c7b629c",
                "deposit": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain"
                },
                "balanceAsset": {
                    "blockchain": "Algorand",
                    "cryptocurrencySymbol": "ALGO",
                    "testAsset": True
                },
                "addressCreationPolicy": "CanCreate"
            }
        ]
    },
    GET_TRANSFER_WITHDRAWALS_BLOCKCHAIN_ENDPOINT: {
        "withdrawals": [
            {
                "id": "1",
                "balanceAsset": {
                    "blockchain": "Algorand",
                    "cryptocurrencySymbol": "ALGO",
                    "testAsset": True
                },
                "balanceAmount": "100",
                "status": "succeeded",
                "createdAt": "2025-01-27T19:15:22Z",
                "finalizedAt": "2025-01-27T19:20:22Z",
                "events": [
                    {
                        "status": "succeeded",
                        "message": "message",
                        "createdAt": "2025-01-27T19:15:22Z"
                    }
                ],
                "destination": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "ORWGX5IZGKJRITXAXPJVW4YI2PUP4AJG2IE6X2XIAPJRD5XXI4LJAS4LNE",
                    "addressTag": "383BDE10FB51489DEBBD",
                    "amount": "100",
                    "blockchainTxId": "WN6FUAX5PQKVM3K7S76FITTR4BSVWR2AFKWENBI2NCTLT4ZOPZNA"
                }
            }
        ]
    },
    POST_TRANSFER_WITHDRAWALS_BLOCKCHAIN_ENDPOINT: {
        "id": "1",
        "balanceAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "balanceAmount": "2",
        "status": "pending",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z",
        "events": [
            {
                "status": "pending",
                "message": "2",
                "createdAt": "2019-08-24T14:15:22Z"
            }
        ],
        "destination": {
            "asset": {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            "transferMethod": "PublicBlockchain",
            "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
            "addressTag": "223797B6A324B30583C4",
            "amount": "2",
            "blockchainTxId": "2"
        }
    },
    GET_TRANSFER_WITHDRAWALS_FIAT_ENDPOINT: {
        "withdrawals": [
            {
                "id": "1",
                "balanceAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "balanceAmount": "2",
                "status": "pending",
                "createdAt": "2019-08-24T14:15:22Z",
                "finalizedAt": "2019-08-24T14:15:22Z",
                "events": [
                    {
                        "status": "pending",
                        "message": "2",
                        "createdAt": "2019-08-24T14:15:22Z"
                    }
                ],
                "destination": {
                    "asset": {
                        "nationalCurrencyCode": "ADP",
                        "testAsset": True
                    },
                    "transferMethod": "Iban",
                    "accountHolder": {
                        "name": "2",
                        "city": "2",
                        "country": "2",
                        "subdivision": "2",
                        "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                        "postalCode": "2"
                    },
                    "iban": "2",
                    "amount": "2",
                    "referenceId": "2"
                }
            }
        ]
    },
    POST_TRANSFER_WITHDRAWALS_FIAT_ENDPOINT: {
        "id": "1",
        "balanceAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "balanceAmount": "2",
        "status": "pending",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z",
        "events": [
            {
                "status": "pending",
                "message": "2",
                "createdAt": "2019-08-24T14:15:22Z"
            }
        ],
        "destination": {
            "asset": {
                "nationalCurrencyCode": "ADP",
                "testAsset": True
            },
            "transferMethod": "Iban",
            "accountHolder": {
                "name": "2",
                "city": "2",
                "country": "2",
                "subdivision": "2",
                "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                "postalCode": "2"
            },
            "iban": "2",
            "amount": "2",
            "referenceId": "2"
        }
    },
    GET_TRANSFER_WITHDRAWALS_PEERACCOUNT_ENDPOINT: {
        "withdrawals": [
            {
                "id": "1",
                "balanceAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "balanceAmount": "2",
                "status": "pending",
                "createdAt": "2019-08-24T14:15:22Z",
                "finalizedAt": "2019-08-24T14:15:22Z",
                "events": [
                    {
                        "status": "pending",
                        "message": "2",
                        "createdAt": "2019-08-24T14:15:22Z"
                    }
                ],
                "destination": {
                    "asset": {
                        "nationalCurrencyCode": "ADP",
                        "testAsset": True
                    },
                    "transferMethod": "PeerAccountTransfer",
                    "accountId": "2",
                    "amount": "2",
                    "referenceId": "2"
                }
            }
        ]
    },
    POST_TRANSFER_WITHDRAWALS_PEERACCOUNT_ENDPOINT: {
        "id": "1",
        "balanceAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "balanceAmount": "2",
        "status": "pending",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z",
        "events": [
            {
                "status": "pending",
                "message": "2",
                "createdAt": "2019-08-24T14:15:22Z"
            }
        ],
        "destination": {
            "asset": {
                "nationalCurrencyCode": "ADP",
                "testAsset": True
            },
            "transferMethod": "PeerAccountTransfer",
            "accountId": "2",
            "amount": "2",
            "referenceId": "2"
        }
    },
    GET_TRANSFER_WITHDRAWALS_SUBACCOUNT_ENDPOINT: {
        "withdrawals": [
            {
                "id": "1",
                "balanceAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "balanceAmount": "2",
                "status": "pending",
                "createdAt": "2019-08-24T14:15:22Z",
                "finalizedAt": "2019-08-24T14:15:22Z",
                "events": [
                    {
                        "status": "pending",
                        "message": "2",
                        "createdAt": "2019-08-24T14:15:22Z"
                    }
                ],
                "destination": {
                    "asset": {
                        "nationalCurrencyCode": "ADP",
                        "testAsset": True
                    },
                    "transferMethod": "InternalTransfer",
                    "accountId": "2",
                    "amount": "2"
                }
            }
        ]
    },
    POST_TRANSFER_WITHDRAWALS_SUBACCOUNT_ENDPOINT: {
        "id": "1",
        "balanceAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "balanceAmount": "2",
        "status": "pending",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z",
        "events": [
            {
                "status": "pending",
                "message": "2",
                "createdAt": "2019-08-24T14:15:22Z"
            }
        ],
        "destination": {
            "asset": {
                "nationalCurrencyCode": "ADP",
                "testAsset": True
            },
            "transferMethod": "InternalTransfer",
            "accountId": "2",
            "amount": "2"
        }
    },
    GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ENDPOINT: {
        "withdrawals": [
            {
                "id": "1",
                "balanceAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "balanceAmount": "2",
                "status": "pending",
                "createdAt": "2019-08-24T14:15:22Z",
                "finalizedAt": "2019-08-24T14:15:22Z",
                "events": [
                    {
                        "status": "pending",
                        "message": "2",
                        "createdAt": "2019-08-24T14:15:22Z"
                    }
                ],
                "destination": {
                    "asset": {
                        "nationalCurrencyCode": "ADP",
                        "testAsset": True
                    },
                    "transferMethod": "PeerAccountTransfer",
                    "accountId": "2",
                    "amount": "2",
                    "referenceId": "2"
                }
            }
        ]
    },
    GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_ENDPOINT: {
        "id": "1",
        "balanceAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "balanceAmount": "2",
        "status": "pending",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z",
        "events": [
            {
                "status": "pending",
                "message": "2",
                "createdAt": "2019-08-24T14:15:22Z"
            }
        ],
        "destination": {
            "asset": {
                "nationalCurrencyCode": "ADP",
                "testAsset": True
            },
            "transferMethod": "PeerAccountTransfer",
            "accountId": "2",
            "amount": "2",
            "referenceId": "2"
        }
    },
    GET_ACCOUNT_TRANSFERS_DEPOSITS_ENDPOINT: {
        "deposits": [
            {
                "id": "1",
                "balanceAsset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "balanceAmount": "2",
                "source": {
                    "asset": {
                        "nationalCurrencyCode": "ADP",
                        "testAsset": True
                    },
                    "transferMethod": "PeerAccountTransfer",
                    "accountId": "2",
                    "amount": "2",
                    "referenceId": "2"
                },
                "depositAddressId": "2",
                "status": "pending",
                "createdAt": "2019-08-24T14:15:22Z",
                "finalizedAt": "2019-08-24T14:15:22Z"
            }
        ]
    },
    GET_ACCOUNT_TRANSFERS_DEPOSITS_ID_ENDPOINT: {
        "id": "1",
        "balanceAsset": {
            "nationalCurrencyCode": "ADP",
            "testAsset": True
        },
        "balanceAmount": "2",
        "source": {
            "asset": {
                "nationalCurrencyCode": "ADP",
                "testAsset": True
            },
            "transferMethod": "PeerAccountTransfer",
            "accountId": "2",
            "amount": "2",
            "referenceId": "2"
        },
        "depositAddressId": "2",
        "status": "pending",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z"
    },
    POST_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT: {
        "id": "1",
        "destination": {
            "asset": {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            "transferMethod": "PublicBlockchain",
            "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
            "addressTag": "223797B6A324B30583C4"
        },
        "status": "enabled"
    },
    GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT: {
        "addresses": [
            {
                "id": "1",
                "destination": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                },
                "status": "enabled"
            }
        ]
    },
    GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT: {
        "id": "1",
        "destination": {
            "asset": {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            "transferMethod": "PublicBlockchain",
            "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
            "addressTag": "223797B6A324B30583C4"
        },
        "status": "enabled"
    },
    DELETE_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT: {
        "message": "2",
        "errorType": "schema-error",
        "propertyName": "/topLevelProperyName/childPropertyName/thirdLevelPropertyName",
        "requestPart": "params"
    },
    POST_ACCOUNT_COLLATERAL_LINK_ENDPOINT: {
        "id": "1",
        "status": "Eligible",
        "eligibleCollateralAssets": [
            {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            {
                "blockchain": "Ethereum",
                "cryptocurrencySymbol": "ETH",
                "testAsset": True
            }
        ]
    },
    GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT: {
        "collateralLinks": []
    },
    POST_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT: {
        "id": "1",
        "address": {
            "asset": {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            "transferMethod": "PublicBlockchain",
            "address": "ORWGX5IZGKJRITXAXPJVW4YI2PUP4AJG2IE6X2XIAPJRD5XXI4LJAS4LNE",
            "addressTag": "383BDE10FB51489DEBBD"
        },
        "recoveryAccountId": "12"
    },
    GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ID_ENDPOINT: {
        "id": "1",
        "address": {
            "asset": {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            "transferMethod": "PublicBlockchain",
            "address": "ORWGX5IZGKJRITXAXPJVW4YI2PUP4AJG2IE6X2XIAPJRD5XXI4LJAS4LNE",
            "addressTag": "383BDE10FB51489DEBBD"
        },
        "recoveryAccountId": "12"
    },
    GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT: {
        "addresses": [
            {
                "id": "1",
                "address": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "ORWGX5IZGKJRITXAXPJVW4YI2PUP4AJG2IE6X2XIAPJRD5XXI4LJAS4LNE",
                    "addressTag": "383BDE10FB51489DEBBD"
                },
                "recoveryAccountId": "12"
            }
        ]
    },
    POST_ACCOUNT_COLLATERAL_ID_INTENT_DEPOSITS_ENDPOINT: {
        "id": "1",
        "status": "Approved",
        "asset": {
            "blockchain": "Algorand",
            "cryptocurrencySymbol": "ADA",
            "testAsset": False
        },
        "amount": "100",
        "approvalRequest": {
            "fireblocksIntentId": "string",
            "partnerIntentId": "string"
        }
    },
    POST_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT: {
        "collateralTxId": "0.8e4cfce8-0182-4c6d-b9dd-a291c105e1d2.0.5a814998-ec0f-4f1c-92bf-fb5f7dc09ea2",
        "approvalRequest": {
            "fireblocksIntentId": "fireblocksIntentId",
            "partnerIntentId": "partnerIntentId"
        }
    },
    GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT: {
        "transactions": [
            {
                "id": "1",
                "status": "Pending",
                "collateralTxId": "0.8e4cfce8-0182-4c6d-b9dd-a291c105e1d2.0.5a814998-ec0f-4f1c-92bf-fb5f7dc09ea2",
                "approvalRequest": {
                    "fireblocksIntentId": "fireblocksIntentId",
                    "partnerIntentId": "partnerIntentId"
                },
                "amount": "2"
            }
        ]
    },
    GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_COLLATERALTXID_ENDPOINT: {
        "id": "1",
        "status": "Pending",
        "collateralTxId": "0.8e4cfce8-0182-4c6d-b9dd-a291c105e1d2.0.5a814998-ec0f-4f1c-92bf-fb5f7dc09ea2",
        "approvalRequest": {
            "fireblocksIntentId": "fireblocksIntentId",
            "partnerIntentId": "partnerIntentId"
        },
        "amount": "2"
    },
    POST_ACCOUNT_COLLATERAL_ID_INTENT_WITHDRAWALS_ENDPOINT: {
        "id": "2",
        "amount": "100",
        "destinationAddress": {
            "asset": {
                "blockchain": "Algorand",
                "cryptocurrencySymbol": "ALGO",
                "testAsset": True
            },
            "transferMethod": "PublicBlockchain",
            "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
            "addressTag": "223797B6A324B30583C4"
        },
        "approvalRequest": {
            "fireblocksIntentId": "fireblocksIntentId",
            "partnerIntentId": "partnerIntentId"
        },
        "status": "Approved",
    },
    POST_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT: {
        "id": "1",
        "collateralTxId": "0.8e4cfce8-0182-4c6d-b9dd-a291c105e1d2.0.5a814998-ec0f-4f1c-92bf-fb5f7dc09ea2",
        "status": "Pending",
        "approvalRequest": {
            "fireblocksIntentId": "fireblocksIntentId",
            "partnerIntentId": "partnerIntentId"
        },
        "rejectionReason": "azov oti"
    },
    GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT: {
        "transactions": [
            {
                "id": "1",
                "collateralTxId": "0.8e4cfce8-0182-4c6d-b9dd-a291c105e1d2.0.5a814998-ec0f-4f1c-92bf-fb5f7dc09ea2",
                "status": "Pending",
                "approvalRequest": {
                    "fireblocksIntentId": "fireblocksIntentId",
                    "partnerIntentId": "partnerIntentId"
                },
                "rejectionReason": "muhahaha"
            }
        ]
    },
    GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_ENDPOINT: {
        "id": "1",
        "collateralTxId": "0.8e4cfce8-0182-4c6d-b9dd-a291c105e1d2.0.5a814998-ec0f-4f1c-92bf-fb5f7dc09ea2",
        "status": "Pending",
        "approvalRequest": {
            "fireblocksIntentId": "fireblocksIntentId",
            "partnerIntentId": "partnerIntentId"
        },
        "rejectionReason": "shtok"
    },
    POST_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT: {
        "settlementVersion": "2",
        "withdrawInstructions": [
            {
                "amount": "2",
                "fee": "0.002",
                "sourceAddress": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                }
            }
        ],
        "depositInstructions": [
            {
                "amount": "2",
                "destinationAddress": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                }
            }
        ]
    },
    GET_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT: {
        "settlementVersion": "2",
        "withdrawInstructions": [
            {
                "amount": "2",
                "fee": "0.002",
                "sourceAddress": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                }
            }
        ],
        "depositInstructions": [
            {
                "amount": "2",
                "destinationAddress": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                }
            }
        ]
    },
    GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_ENDPOINT: {
        "settlementVersion": "2",
        "withdrawTransactions": [
            {
                "amount": "2",
                "fee": "0.002",
                "sourceAddress": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                },
                "status": "NOT_FOUND",
                "rejectionReason": "Stam ki ein li koah lehapes"
            }
        ],
        "depositTransactions": [
            {
                "amount": "2",
                "destinationAddress": {
                    "asset": {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    "transferMethod": "PublicBlockchain",
                    "address": "J4NOFD4VBNJ35F2MEII4HRAADNPJ7QFYAKESYKSEWWGJUXG64IATUVZRMQ",
                    "addressTag": "223797B6A324B30583C4"
                },
                "status": "NOT_FOUND",
                "rejectionReason": "Lo Motze"
            }
        ],
        "status": "Invalid"
    },
    GET_TRADING_BOOKS_ID_ENDPOINT: {
        "id": "BTC/USDC",
        "description": "Bitcoin book",
        "baseAsset": {
            "blockchain": "Bitcoin",
            "cryptocurrencySymbol": "BTC"
        },
        "quoteAsset": {
            "assetId": "f0844d82-7097-4521-95bc-d843724a893e"
        }
    },
    GET_TRADING_BOOKS_ID_ASKS_ENDPOINT: {
        "asks": [
            {
                "id": "EADAC726-414B-4C5B-B26A-8A616446BDB0",
                "price": "29312.03",
                "amount": "9.21634",
                "totalPrice": "270149.63",
                "side": "SELL"
            },
            {
                "id": "23631CE5-123B-4163-A6CD-6BF3CE5521C6",
                "price": "29315.97",
                "amount": "22.33346",
                "totalPrice": "654727.04",
                "side": "SELL"
            },
            {
                "id": "375C2D0A-2874-4FCE-A860-068856D05A87",
                "price": "29316.95",
                "amount": "9.30764",
                "totalPrice": "272871.62",
                "side": "SELL"
            },
            {
                "id": "E577CE57-57BE-49F4-ACA9-DA8EA0F560BD",
                "price": "29317.14",
                "amount": "7.56552",
                "totalPrice": "221799.41",
                "side": "SELL"
            },
            {
                "id": "E776FAF0-B9BB-414B-8519-CB01D088FAC2",
                "price": "29317.38",
                "amount": "9.87465",
                "totalPrice": "289498.87",
                "side": "SELL"
            }
        ]
    },
    GET_TRADING_BOOKS_ID_BIDS_ENDPOINT: {
        "bids": [
            {
                "id": "92946569-74FE-42BD-9898-CBD03A5D407B",
                "price": "29312.03",
                "amount": "9.21634",
                "totalPrice": "270149.63",
                "side": "BUY"
            },
            {
                "id": "F69C17BB-9E2A-4159-8938-8B142F55B4BE",
                "price": "29310.42",
                "amount": "0.00091",
                "totalPrice": "26.67",
                "side": "BUY"
            },
            {
                "id": "E7042B8A-D467-4144-AC53-92C4A96C2A84",
                "price": "29310.35",
                "amount": "0.027",
                "totalPrice": "791.38",
                "side": "BUY"
            },
            {
                "id": "6A3444BC-34D1-411B-B505-ADE557307C62",
                "price": "29310.34",
                "amount": "0.4275",
                "totalPrice": "12530.17",
                "side": "BUY"
            },
            {
                "id": "27C49660-AC51-409D-A6C9-5E5BB0FFFACE",
                "price": "29310.27",
                "amount": "0.01412",
                "totalPrice": "413.86",
                "side": "BUY"
            }
        ]
    },
    GET_TRADING_BOOKS_ID_HISTORY_ENDPOINT: {
        "trades": [
            {
                "id": "1",
                "amount": "2",
                "price": "1",
                "totalPrice": "1",
                "side": "SELL",
                "finalizedAt": "2019-08-24T14:15:22Z"
            }
        ]
    },
    GET_ACCOUNT_TRADING_ORDERS_ENDPOINT: {
        "orders": [
            {
                "bookId": "2",
                "side": "SELL",
                "timeInForce": "GOOD_TILL_CANCELED",
                "baseAssetQuantity": "2",
                "orderType": "LIMIT",
                "quoteAssetPrice": "1",
                "id": "1",
                "status": "TRADING",
                "createdAt": "2019-08-24T14:15:22Z",
                "finalizedAt": "2019-08-24T14:15:22Z"
            }
        ]
    },
    POST_ACCOUNT_TRADING_ORDERS_ENDPOINT: {
        "id": "cf091554-f2b8-4cea-9783-2a7e5065b549",
        "status": "TRADING",
        "bookId": "BTC_USDC",
        "side": "SELL",
        "orderType": "LIMIT",
        "timeInForce": "GOOD_TILL_CANCELED",
        "baseAssetQuantity": "10",
        "quoteAssetPrice": "20000",
        "createdAt": "2023-06-02T19:45:26.550Z"
    },
    GET_ACCOUNT_TRADING_ORDERS_ID_ENDPOINT: {
        "bookId": "2",
        "side": "SELL",
        "timeInForce": "GOOD_TILL_CANCELED",
        "baseAssetQuantity": "2",
        "orderType": "MARKET",
        "id": "1",
        "status": "TRADING",
        "createdAt": "2019-08-24T14:15:22Z",
        "finalizedAt": "2019-08-24T14:15:22Z",
        "trades": [
            {
                "id": "1",
                "amount": "2",
                "price": "1",
                "totalPrice": "1",
                "side": "SELL",
                "finalizedAt": "2019-08-24T14:15:22Z"
            }
        ]
    },
    DELETE_ACCOUNT_TRADING_ORDERS_ID_ENDPOINT: {
        "message": "2",
        "errorType": "schema-error",
        "propertyName": "/topLevelProperyName/childPropertyName/thirdLevelPropertyName",
        "requestPart": "params"
    }
}

COLLATERAL_CODES = {
    POST_COLLATERAL_INITIATE_ENDPOINT: 200,
    POST_COLLATERAL_ADDRESS_ENDPOINT: 200,
    POST_COLLATERAL_WITHDRAW_ENDPOINT: 200,
    POST_COLLATERAL_SETTLEMENT_ENDPOINT: 200,
    POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT: 200,
    GET_COLLATERAL_SETTLEMENT_ENDPOINT: 200,
    POST_COLLATERAL_ADD_ENDPOINT: 200,
}

COLLATERAL_ID = None


@app.route(POST_COLLATERAL_INITIATE_ENDPOINT, methods=[POST_COLLATERAL_INITIATE_METHOD])
def collateral_initiate():
    global COLLATERAL_ID
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_COLLATERAL_INITIATE_METHOD,
                               POST_COLLATERAL_INITIATE_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          POST_COLLATERAL_INITIATE_METHOD,
                                          POST_COLLATERAL_INITIATE_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": "OFF-EXCHANGE-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400
    params = json.loads(request.data)
    response = COLLATERAL_RESPONSES[POST_COLLATERAL_INITIATE_ENDPOINT]
    if not "collateralId" in response:
        if COLLATERAL_ID:
            response["collateralId"] = COLLATERAL_ID
        else:
            response["collateralId"] = params["collateralId"]
            COLLATERAL_ID = response["collateralId"]

    code = COLLATERAL_CODES[POST_COLLATERAL_INITIATE_ENDPOINT]
    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response), code

    # Add response headers and return the modified response
    return addResponseHeaders(response, request.headers, POST_COLLATERAL_INITIATE_METHOD,
                              POST_COLLATERAL_INITIATE_ENDPOINT), code


@app.route(POST_COLLATERAL_ADDRESS_ENDPOINT, methods=[POST_COLLATERAL_ADDRESS_METHOD])
def collateral_address():
    app.logger.info(f'request .data: {request.data}')
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_COLLATERAL_ADDRESS_METHOD,
                               POST_COLLATERAL_ADDRESS_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          POST_COLLATERAL_ADDRESS_METHOD,
                                          POST_COLLATERAL_ADDRESS_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": f'OFF-EXCHANGE-SIGNATURE is invalid!"{request.headers}"'
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    response_data = COLLATERAL_RESPONSES[POST_COLLATERAL_ADDRESS_ENDPOINT]
    code = COLLATERAL_CODES[POST_COLLATERAL_ADDRESS_ENDPOINT]
    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response_data), code

    # Add response headers and return the modified response
    return addResponseHeaders(response_data, request.headers, POST_COLLATERAL_ADDRESS_METHOD,
                              POST_COLLATERAL_ADDRESS_ENDPOINT), code


@app.route(POST_COLLATERAL_ADD_ENDPOINT, methods=[POST_COLLATERAL_ADD_METHOD])
def collateral_add():
    app.logger.info(f'request .data: {request.data}')
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_COLLATERAL_ADD_METHOD,
                               POST_COLLATERAL_ADD_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          POST_COLLATERAL_ADD_METHOD,
                                          POST_COLLATERAL_ADD_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": f'OFF-EXCHANGE-SIGNATURE is invalid!"{request.headers}"'
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    response_data = COLLATERAL_RESPONSES[POST_COLLATERAL_ADD_ENDPOINT]
    code = COLLATERAL_CODES[POST_COLLATERAL_ADD_ENDPOINT]
    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response_data), code

    # Add response headers and return the modified response
    return addResponseHeaders(response_data, request.headers, POST_COLLATERAL_ADD_METHOD,
                              POST_COLLATERAL_ADD_ENDPOINT), code


@app.route(POST_COLLATERAL_WITHDRAW_ENDPOINT, methods=[POST_COLLATERAL_WITHDRAW_METHOD])
def collateral_withdraw():
    app.logger.info(f'request.data: {request.data}')
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_COLLATERAL_WITHDRAW_METHOD,
                               POST_COLLATERAL_WITHDRAW_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          POST_COLLATERAL_WITHDRAW_METHOD,
                                          POST_COLLATERAL_WITHDRAW_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": "OFF-EXCHANGE-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400

    # return json.dumps(COLLATERAL_RESPONSES[POST_COLLATERAL_WITHDRAW_ENDPOINT])
    response_data = COLLATERAL_RESPONSES[POST_COLLATERAL_WITHDRAW_ENDPOINT]
    code = COLLATERAL_CODES[POST_COLLATERAL_WITHDRAW_ENDPOINT]

    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response_data), code

    # response_data = {"approved": False, "rejectionReason": "Rejected cus i said"}
    # Add response headers and return the modified response
    return addResponseHeaders(response_data, request.headers, POST_COLLATERAL_WITHDRAW_METHOD,
                              POST_COLLATERAL_WITHDRAW_ENDPOINT), code


@app.route(POST_COLLATERAL_SETTLEMENT_ENDPOINT, methods=[POST_COLLATERAL_SETTLEMENT_METHOD])
def collateral_settlement():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_COLLATERAL_SETTLEMENT_METHOD,
                               POST_COLLATERAL_SETTLEMENT_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          POST_COLLATERAL_SETTLEMENT_METHOD,
                                          POST_COLLATERAL_SETTLEMENT_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": "OFF-EXCHANGE-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400
    # return json.dumps(COLLATERAL_RESPONSES[POST_COLLATERAL_SETTLEMENT_ENDPOINT])
    response_data = COLLATERAL_RESPONSES[POST_COLLATERAL_SETTLEMENT_ENDPOINT]
    code = COLLATERAL_CODES[POST_COLLATERAL_SETTLEMENT_ENDPOINT]

    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response_data), code

    # Add response headers and return the modified response
    return addResponseHeaders(response_data, request.headers, POST_COLLATERAL_SETTLEMENT_METHOD,
                              POST_COLLATERAL_SETTLEMENT_ENDPOINT), code


@app.route(POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT, methods=[POST_COLLATERAL_ENFORCE_SETTLEMENT_METHOD])
def collateral_enforce_settlement():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               POST_COLLATERAL_ENFORCE_SETTLEMENT_METHOD,
                               POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT,
                               request.data.decode('utf-8')):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          POST_COLLATERAL_ENFORCE_SETTLEMENT_METHOD,
                                          POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": "OFF-EXCHANGE-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400
    # return json.dumps(COLLATERAL_RESPONSES[POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT])
    response_data = COLLATERAL_RESPONSES[POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT]
    code = COLLATERAL_CODES[POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT]

    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response_data), code

    # Add response headers and return the modified response
    return addResponseHeaders(response_data, request.headers, POST_COLLATERAL_ENFORCE_SETTLEMENT_METHOD,
                              POST_COLLATERAL_ENFORCE_SETTLEMENT_ENDPOINT), code


@app.route(GET_COLLATERAL_SETTLEMENT_ENDPOINT, methods=[GET_COLLATERAL_SETTLEMENT_METHOD])
def get_collateral_settlement():
    if not validateHeaders(request.headers):
        return json.dumps({
            "error": "Header is missing params!"
        }), 400
    elif not validateAPIKeyHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-KEY is invalid!"
        }), 401
    elif not validateTimestampHeader(request.headers):
        return json.dumps({
            "error": "X-FBAPI-TIMESTAMP is invalid or out of date!"
        }), 400
    elif not validateSignature(request.headers,
                               GET_COLLATERAL_SETTLEMENT_METHOD,
                               GET_COLLATERAL_SETTLEMENT_ENDPOINT,
                               '?' + request.query_string.decode("utf-8")):
        return json.dumps({
            "error": "X-FBAPI-SIGNATURE is invalid!"
        }), 400
    elif not validateOffExchangeSignature(request.headers,
                                          GET_COLLATERAL_SETTLEMENT_METHOD,
                                          GET_COLLATERAL_SETTLEMENT_ENDPOINT,
                                          request.data.decode('utf-8')):
        return json.dumps({
            "error": "OFF-EXCHANGE-SIGNATURE is invalid!"
        }), 400
    elif not validateNonce(request.headers):
        return json.dumps({
            "error": "X-FBAPI-NONCE is invalid!"
        }), 400
    # return json.dumps(COLLATERAL_RESPONSES[POST_COLLATERAL_SETTLEMENT_ENDPOINT])
    response_data = COLLATERAL_RESPONSES[POST_COLLATERAL_SETTLEMENT_ENDPOINT]
    code = COLLATERAL_CODES[GET_COLLATERAL_SETTLEMENT_ENDPOINT]

    if (not toAddOffExchangeResponseHeader(request.headers)):
        return json.dumps(response_data), code

    # Add response headers and return the modified response
    return addResponseHeaders(response_data, request.headers, GET_COLLATERAL_SETTLEMENT_METHOD,
                              GET_COLLATERAL_SETTLEMENT_ENDPOINT), code


WEBHOOK_KEY_PROD = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0+6wd9OJQpK60ZI7qnZG
jjQ0wNFUHfRv85Tdyek8+ahlg1Ph8uhwl4N6DZw5LwLXhNjzAbQ8LGPxt36RUZl5
YlxTru0jZNKx5lslR+H4i936A4pKBjgiMmSkVwXD9HcfKHTp70GQ812+J0Fvti/v
4nrrUpc011Wo4F6omt1QcYsi4GTI5OsEbeKQ24BtUd6Z1Nm/EP7PfPxeb4CP8KOH
clM8K7OwBUfWrip8Ptljjz9BNOZUF94iyjJ/BIzGJjyCntho64ehpUYP8UJykLVd
CGcu7sVYWnknf1ZGLuqqZQt4qt7cUUhFGielssZP9N9x7wzaAIFcT3yQ+ELDu1SZ
dE4lZsf2uMyfj58V8GDOLLE233+LRsRbJ083x+e2mW5BdAGtGgQBusFfnmv5Bxqd
HgS55hsna5725/44tvxll261TgQvjGrTxwe7e5Ia3d2Syc+e89mXQaI/+cZnylNP
SwCCvx8mOM847T0XkVRX3ZrwXtHIA25uKsPJzUtksDnAowB91j7RJkjXxJcz3Vh1
4k182UFOTPRW9jzdWNSyWQGl/vpe9oQ4c2Ly15+/toBo4YXJeDdDnZ5c/O+KKadc
IMPBpnPrH/0O97uMPuED+nI6ISGOTMLZo35xJ96gPBwyG5s2QxIkKPXIrhgcgUnk
tSM7QYNhlftT4/yVvYnk0YcCAwEAAQ==
-----END PUBLIC KEY-----"""
WEBHOOK_KEY_SANDBOX = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+fZuC+0vDYTf8fYnCN6
71iHg98lPHBmafmqZqb+TUexn9sH6qNIBZ5SgYFxFK6dYXIuJ5uoORzihREvZVZP
8DphdeKOMUrMr6b+Cchb2qS8qz8WS7xtyLU9GnBn6M5mWfjkjQr1jbilH15Zvcpz
ECC8aPUAy2EbHpnr10if2IHkIAWLYD+0khpCjpWtsfuX+LxqzlqQVW9xc6z7tshK
eCSEa6Oh8+ia7Zlu0b+2xmy2Arb6xGl+s+Rnof4lsq9tZS6f03huc+XVTmd6H2We
WxFMfGyDCX2akEg2aAvx7231/6S0vBFGiX0C+3GbXlieHDplLGoODHUt5hxbPJnK
IwIDAQAB
-----END PUBLIC KEY-----"""


@app.route(POST_COLLATERAL_NOTIFICATION, methods=[POST_COLLATERAL_NOTIFICATION_METHOD])
def get_collateral_notification():
    app.logger.info(request.data)
    app.logger.info(request.headers)
    return json.dumps({
    }), 200


@app.route(POST_POLINA_DEBUG, methods=[POST_POLINA_DEBUG_METHOD])
def get_polina_debug():
    app.logger.info("SUCESS SUCCESS SUCCESS!!!!")
    return json.dumps({
    }), 200


@app.route(POST_COLLATERAL_RESPONSE_ENDPOINT, methods=[POST_COLLATERAL_RESPONSE_METHOD])
def collateral_response():
    params = json.loads(request.data)

    if not "endpoint" in params:
        return json.dumps({
            "error": "Endpoint field does not exist!"
        }), 400
    elif not "response" in params:
        return json.dumps({
            "error": "Response field does not exist!"
        }), 400

    endpoint = COLLATERAL_BASE_URL + params["endpoint"]

    if not endpoint in COLLATERAL_RESPONSES:
        return json.dumps({
            "error": "Endpoint does not exist!"
        }), 400

    COLLATERAL_RESPONSES[endpoint] = params["response"]
    COLLATERAL_CODES[endpoint] = 200 if not "code" in params else params["code"]
    return "Changed!"


counters = {
    'get_capabilities': 0,
    'get_capabilities_assets': 0,
    'get_capabilities_assets_id': 0,
    'get_capabilities_liquidity_quotes': 0,
    'get_capabilities_trading_books': 0,
    'get_sub_accounts': 0,
    'get_sub_account': 0,
    'get_balances': 0,
    'get_historic_balances': 0,
    'get_liquidity_quotes': 0,
    'post_liquidity_quotes': 0,
    'get_liquidity_quotes_id': 0,
    'post_liquidity_quotes_id': 0,
    'get_withdrawal_methods': 0,
    'get_deposit_methods': 0,
    'post_transfer_withdrawals_blockchain': 0,
    'post_transfer_withdrawals_fiat': 0,
    'post_transfer_withdrawals_peeraccount': 0,
    'post_transfer_withdrawals_subaccount': 0,
    'get_account_transfers_withdrawals': 0,
    'get_account_transfers_withdrawals_id': 0,
    'post_account_transfers_deposits_addresses': 0,
    'get_account_transfers_deposits_addresses': 0,
    'get_account_transfers_deposits_addresses_id': 0,
    'post_account_collateral_link': 0,
    'get_account_collateral_link': 0,
    'post_account_collateral_id_addresses': 0,
    'get_account_collateral_id_addresses': 0,
    'post_account_collateral_id_intent_deposits': 0,
    'post_account_collateral_id_deposits': 0,
    'get_account_collateral_id_deposits': 0,
    'get_account_collateral_id_deposits_txid': 0,
    'post_account_collateral_id_intent_withdrawals': 0,
    'post_account_collateral_id_withdrawals': 0,
    'get_account_collateral_id_withdrawals': 0,
    'get_account_collateral_id_withdrawals_txid': 0,
    'post_account_collateral_id_settlement': 0,
    'get_account_collateral_id_settlement': 0,
    'get_account_collateral_id_settlement_version': 0,
    'trading_books_id': 0
}


def check_limit(endpoint_name):
    return request.args.get('startingAfter', default=None) != None


@app.route(GET_CAPABILITIES_ENDPOINT, methods=[GET_CAPABILITIES_METHOD])
def get_capabilities(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_capabilities')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_CAPABILITIES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_CAPABILITIES_ENDPOINT])


@app.route(GET_CAPABILITIES_ASSETS_ENDPOINT, methods=[GET_CAPABILITIES_ASSETS_METHOD])
def get_capabilities_assets(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_capabilities_assets')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_CAPABILITIES_ASSETS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_CAPABILITIES_ASSETS_ENDPOINT])


@app.route(GET_CAPABILITIES_ASSETS_ID_ENDPOINT, methods=[GET_CAPABILITIES_ASSETS_ID_METHOD])
def get_capabilities_assets_id(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_capabilities_assets_id')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_CAPABILITIES_ASSETS_ID_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_CAPABILITIES_ASSETS_ID_ENDPOINT])


@app.route(GET_CAPABILITIES_LIQUIDITY_QUOTES_ENDPOINT, methods=[GET_CAPABILITIES_LIQUIDITY_QUOTES_METHOD])
def get_capabilities_liquidity_quotes(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                      settlementVersion='1'):
    limit = check_limit('get_capabilities_liquidity_quotes')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_CAPABILITIES_LIQUIDITY_QUOTES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_CAPABILITIES_LIQUIDITY_QUOTES_ENDPOINT])


@app.route(GET_CAPABILITIES_TRADING_BOOKS_ENDPOINT, methods=[GET_CAPABILITIES_TRADING_BOOKS_METHOD])
def get_capabilities_trading_books(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_capabilities_trading_books')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_CAPABILITIES_TRADING_BOOKS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_CAPABILITIES_TRADING_BOOKS_ENDPOINT])


@app.route(GET_SUB_ACCOUNTS_ENDPOINT, methods=[GET_ACCOUNTS_METHOD])
def get_sub_accounts(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_sub_accounts')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_SUB_ACCOUNTS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_SUB_ACCOUNTS_ENDPOINT])


@app.route(GET_SUB_ACCOUNT_ENDPOINT, methods=[GET_SUB_ACCOUNT_METHOD])
def get_sub_account(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_sub_account')
    print(accountId)
    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_SUB_ACCOUNT_ENDPOINT].keys())[0]: []})
    if accountId == '2':
        return json.dumps({
        "id": "2",
        "title": "res test sub",
        "description": "res test sub",
        "balances": [
            {
                "id": "1",
                "asset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "availableAmount": "10",
                "lockedAmount": "1"
            },
            {
                "id": "dc662581-42d3-4128-8454-3ce4bdb44329",
                "asset": {
                    "cryptocurrencySymbol": "ETH",
                    "testAsset": True
                },
                "availableAmount": "54604.0132",
                "lockedAmount": "1"
            },
            {
                "id": "5cfed176-b745-4759-9611-6b0b699f1422",
                "asset": {
                    "cryptocurrencySymbol": "ALGO",
                    "testAsset": True
                },
                "availableAmount": "795.608",
                "lockedAmount": "1"
            },
        ],
        "status": "active",
    })
    if accountId == '3':
        return json.dumps({
        "id": "3",
        "title": "res test sub 2",
        "description": "res test sub 2",
        "balances": [
            {
                "id": "1",
                "asset": {
                    "nationalCurrencyCode": "ADP",
                    "testAsset": True
                },
                "availableAmount": "10",
                "lockedAmount": "1"
            },
            {
                "id": "dc662581-42d3-4128-8454-3ce4bdb44329",
                "asset": {
                    "cryptocurrencySymbol": "ETH",
                    "testAsset": True
                },
                "availableAmount": "54604.0132",
                "lockedAmount": "1"
            },
            {
                "id": "5cfed176-b745-4759-9611-6b0b699f1422",
                "asset": {
                    "cryptocurrencySymbol": "ALGO",
                    "testAsset": True
                },
                "availableAmount": "795.608",
                "lockedAmount": "1"
            },
        ],
        "status": "active",
    })
    return json.dumps(COLLATERAL_RESPONSES[GET_SUB_ACCOUNT_ENDPOINT])


@app.route(GET_BALANCES_ENDPOINT, methods=[GET_BALANCES_METHOD])
def get_balances(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_balances')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_BALANCES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_BALANCES_ENDPOINT])


@app.route(GET_HISTORIC_BALANCES_ENDPOINT, methods=[GET_HISTORIC_BALANCES_METHOD])
def get_historic_balances(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_historic_balances')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_HISTORIC_BALANCES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_HISTORIC_BALANCES_ENDPOINT])


@app.route(GET_LIQUIDITY_QUOTES_ENDPOINT, methods=[GET_LIQUIDITY_QUOTES_METHOD])
def get_liquidity_quotes(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_liquidity_quotes')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_LIQUIDITY_QUOTES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_LIQUIDITY_QUOTES_ENDPOINT])


@app.route(POST_LIQUIDITY_QUOTES_ENDPOINT, methods=[POST_LIQUIDITY_QUOTES_METHOD])
def post_liquidity_quotes(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_LIQUIDITY_QUOTES_ENDPOINT])


@app.route(GET_LIQUIDITY_QUOTES_ID_ENDPOINT, methods=[GET_LIQUIDITY_QUOTES_ID_METHOD])
def get_liquidity_quotes_id(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_liquidity_quotes_id')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_LIQUIDITY_QUOTES_ID_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_LIQUIDITY_QUOTES_ID_ENDPOINT])


@app.route(POST_LIQUIDITY_QUOTES_ID_ENDPOINT, methods=[POST_LIQUIDITY_QUOTES_ID_METHOD])
def post_liquidity_quotes_id(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_LIQUIDITY_QUOTES_ID_ENDPOINT])


@app.route(GET_WITHDRAWAL_METHODS_ENDPOINT, methods=[GET_WITHDRAWAL_METHODS_METHOD])
def get_withdrawal_methods(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_withdrawal_methods')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_WITHDRAWAL_METHODS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_WITHDRAWAL_METHODS_ENDPOINT])


@app.route(GET_DEPOSIT_METHODS_ENDPOINT, methods=[GET_DEPOSIT_METHODS_METHOD])
def get_deposit_methods(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_deposit_methods')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_DEPOSIT_METHODS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_DEPOSIT_METHODS_ENDPOINT])


@app.route(POST_TRANSFER_WITHDRAWALS_BLOCKCHAIN_ENDPOINT, methods=[POST_TRANSFER_WITHDRAWALS_BLOCKCHAIN_METHOD])
def post_transfer_withdrawals_blockchain(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                         settlementVersion='1'):
    logging.debug('Oz PII test')
    logging.debug(request.get_json())
    return json.dumps(COLLATERAL_RESPONSES[POST_TRANSFER_WITHDRAWALS_BLOCKCHAIN_ENDPOINT])


@app.route(POST_TRANSFER_WITHDRAWALS_FIAT_ENDPOINT, methods=[POST_TRANSFER_WITHDRAWALS_FIAT_METHOD])
def post_transfer_withdrawals_fiat(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_TRANSFER_WITHDRAWALS_FIAT_ENDPOINT])


@app.route(POST_TRANSFER_WITHDRAWALS_PEERACCOUNT_ENDPOINT, methods=[POST_TRANSFER_WITHDRAWALS_PEERACCOUNT_METHOD])
def post_transfer_withdrawals_peeraccount(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                          settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_TRANSFER_WITHDRAWALS_PEERACCOUNT_ENDPOINT])


@app.route(POST_TRANSFER_WITHDRAWALS_SUBACCOUNT_ENDPOINT, methods=[POST_TRANSFER_WITHDRAWALS_SUBACCOUNT_METHOD])
def post_transfer_withdrawals_subaccount(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                         settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_TRANSFER_WITHDRAWALS_SUBACCOUNT_ENDPOINT])


@app.route(GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ENDPOINT, methods=[GET_ACCOUNT_TRANSFERS_WITHDRAWALS_METHOD])
def get_account_transfers_withdrawals(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                      settlementVersion='1'):
    limit = check_limit('get_account_transfers_withdrawals')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ENDPOINT])


@app.route(GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_ENDPOINT, methods=[GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_METHOD])
def get_account_transfers_withdrawals_id(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                         settlementVersion='1'):
    limit = check_limit('get_account_transfers_withdrawals_id')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_WITHDRAWALS_ID_ENDPOINT])


@app.route(POST_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT,
           methods=[POST_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_METHOD])
def post_account_transfers_deposits_addresses(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                              settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT])


@app.route(GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT, methods=[GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_METHOD])
def get_account_transfers_deposits_addresses(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                             settlementVersion='1'):
    limit = check_limit('get_account_transfers_deposits_addresses')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ENDPOINT])


@app.route(GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT,
           methods=[GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_METHOD])
def get_account_transfers_deposits_addresses_id(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                                settlementVersion='1'):
    limit = check_limit('get_account_transfers_deposits_addresses_id')

    if limit:
        return json.dumps(
            {list(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_TRANSFERS_DEPOSITS_ADDRESSES_ID_ENDPOINT])


@app.route(POST_ACCOUNT_COLLATERAL_LINK_ENDPOINT, methods=[POST_ACCOUNT_COLLATERAL_LINK_METHOD])
def post_account_collateral_link(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    request_data = request.get_json() or {}
    print(request_data)
    collateral_id = request_data.get('collateralId')
    collateral_signers = request_data.get('collateralSigners', [])
    env = request_data.get('env')

    if not collateral_id or not env:
        return json.dumps({"error": "Missing required fields: collateralId, collateralSigners, or env"}), 400

    response = {"id": "1",
                "status": "Eligible",
                "eligibleCollateralAssets": [
                    {
                        "blockchain": "Algorand",
                        "cryptocurrencySymbol": "ALGO",
                        "testAsset": True
                    },
                    {
                        "blockchain": "Ethereum",
                        "cryptocurrencySymbol": "ETH",
                        "testAsset": True
                    }
                ],
                "collateralId": collateral_id,
                "collateralSigners": collateral_signers,
                "env": env
                }
    print(response)
    return json.dumps(response)


@app.route(GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT, methods=[GET_ACCOUNT_COLLATERAL_LINK_METHOD])
def get_account_collateral_link(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('get_account_collateral_link')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_LINK_ENDPOINT])


@app.route(POST_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT, methods=[POST_ACCOUNT_COLLATERAL_ID_ADDRESSES_METHOD])
def post_account_collateral_id_addresses(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                         settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT])


@app.route(GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT, methods=[GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_METHOD])
def get_account_collateral_id_addresses(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                        settlementVersion='1'):
    limit = check_limit('get_account_collateral_id_addresses')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_ADDRESSES_ENDPOINT])


@app.route(POST_ACCOUNT_COLLATERAL_ID_INTENT_DEPOSITS_ENDPOINT,
           methods=[POST_ACCOUNT_COLLATERAL_ID_INTENT_DEPOSITS_METHOD])
def post_account_collateral_id_intent_deposits(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                               settlementVersion='1'):
    random_id = "22"
    request_data = request.get_json() or {}
    intent_request = request_data.get("intentApprovalRequest", {})
    fireblocks_intent_id = intent_request.get("fireblocksIntentId", "")

    response = {
        "id": random_id,
        "status": "Approved",
        "asset": request_data["asset"],
        "amount": request_data["amount"],
        "approvalRequest": {
            "fireblocksIntentId": fireblocks_intent_id,
            "partnerIntentId": "444"
        }
    }
    print(request_data)
    return json.dumps(response)


@app.route(POST_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT, methods=[POST_ACCOUNT_COLLATERAL_ID_DEPOSITS_METHOD])
def post_account_collateral_id_deposits(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                        settlementVersion='1'):
    limit = check_limit('post_account_collateral_id_deposits')

    request_data = request.get_json() or {}
    print(request_data)
    collateral_tx_id = request_data.get('collateralTxId')

    if not collateral_tx_id:
        return json.dumps({"error": "Missing required fields: collateralTxId"}), 400

    response = {
        "id": "1",
        "status": "Credited",
        "collateralTxId": collateral_tx_id,
        "approvalRequest": request_data.get('approvalRequest')
    }
    print(response)
    return json.dumps(response)


@app.route(GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT, methods=[GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_METHOD])
def get_account_collateral_id_deposits(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                       settlementVersion='1'):
    limit = check_limit('get_account_collateral_id_deposits')
    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_ENDPOINT])


@app.route(GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_COLLATERALTXID_ENDPOINT,
           methods=[GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_COLLATERALTXID_METHOD])
def get_account_collateral_id_deposits_txid(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                            settlementVersion='1'):
    limit = check_limit('get_account_collateral_id_deposits_txid')
    collateral_tx_id = request.args.get('collateralTxId')
    response = {
        "id": "1",
        "status": "Approved",
        "collateralTxId": collateral_tx_id,
        "approvalRequest": {
            "fireblocksIntentId": collateral_tx_id,
            "partnerIntentId": "444"
        }
    }
    if limit:
        return json.dumps(
            {list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_DEPOSITS_COLLATERALTXID_ENDPOINT].keys())[0]: []})
    return json.dumps({"errorType": "not-found", "message": "read the error type..."}), 404


@app.route(POST_ACCOUNT_COLLATERAL_ID_INTENT_WITHDRAWALS_ENDPOINT,
           methods=[POST_ACCOUNT_COLLATERAL_ID_INTENT_WITHDRAWALS_METHOD])
def post_account_collateral_id_intent_withdrawals(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                                  settlementVersion='1'):
    random_id = "333"
    request_data = request.get_json() or {}
    intent_request = request_data.get("intentApprovalRequest", {})
    fireblocks_intent_id = intent_request.get("fireblocksIntentId", "")

    response = {
        "id": random_id,
        "status": "Approved",
        "destinationAddress": request_data["destinationAddress"],
        "amount": request_data["amount"],
        "approvalRequest": {
            "fireblocksIntentId": fireblocks_intent_id,
            "partnerIntentId": "555"
        }
    }

    return json.dumps(response)


@app.route(POST_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT, methods=[POST_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_METHOD])
def post_account_collateral_id_withdrawals(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                           settlementVersion='1'):
    request_data = request.get_json() or {}
    print(request_data)
    collateral_tx_id = request_data.get('collateralTxId')

    if not collateral_tx_id:
        return json.dumps({"error": "Missing required fields: collateralTxId"}), 400

    response = {
        "id": "555",
        "status": "Approved",
        "collateralTxId": collateral_tx_id,
        "approvalRequest": request_data.get('approvalRequest')
    }
    print(response)
    return json.dumps(response)


@app.route(GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT, methods=[GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_METHOD])
def get_account_collateral_id_withdrawals(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                          settlementVersion='1'):
    limit = check_limit('get_account_collateral_id_withdrawals')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_ENDPOINT])


@app.route(GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_ENDPOINT,
           methods=[GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_METHOD])
def get_account_collateral_id_withdrawals_txid(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                               settlementVersion='1'):
    limit = check_limit('get_account_collateral_id_withdrawals_txid')

    if limit:
        return json.dumps(
            {list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_WITHDRAWALS_COLLATERALTXID_ENDPOINT])


@app.route(POST_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT, methods=[POST_ACCOUNT_COLLATERAL_ID_SETTLEMENT_METHOD])
def post_account_collateral_id_settlement(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                          settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[POST_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT])


@app.route(GET_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT, methods=[GET_ACCOUNT_COLLATERAL_ID_SETTLEMENT_METHOD])
def get_account_collateral_id_settlement(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                         settlementVersion='1'):
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_SETTLEMENT_ENDPOINT])


@app.route(GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_ENDPOINT,
           methods=[GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_METHOD])
def get_account_collateral_id_settlement_version(accountId='1', id='1', collateralId='1', collateralTxId='1',
                                                 settlementVersion='1'):
    limit = check_limit('get_capabilities')

    if limit:
        return json.dumps(
            {list(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_ACCOUNT_COLLATERAL_ID_SETTLEMENTS_VERSION_ENDPOINT])


@app.route(GET_TRADING_BOOKS_ID_ENDPOINT, methods=[GET_TRADING_BOOKS_ID_METHOD])
def trading_books_id(accountId='1', id='1', collateralId='1', collateralTxId='1', settlementVersion='1'):
    limit = check_limit('trading_books_id')

    if limit:
        return json.dumps({list(COLLATERAL_RESPONSES[GET_TRADING_BOOKS_ID_ENDPOINT].keys())[0]: []})
    return json.dumps(COLLATERAL_RESPONSES[GET_TRADING_BOOKS_ID_ENDPOINT])
