from flask import Flask, render_template, request
from datetime import datetime
import requests
import socket


app = Flask(__name__)

COINGECKO_API = "https://api.coingecko.com/api/v3/simple/price"

# Save original getaddrinfo
socket._orig_getaddrinfo = socket.getaddrinfo
CRYPTO_COINS = [
    "bitcoin",
    "ethereum",
    "ripple",
    "solana",
    "cardano",
    "dogecoin",
    "litecoin",
    "polkadot",
    "tron",
    "avalanche-2"
]


def fetch_prices():
    params = {
        "ids": ",".join(CRYPTO_COINS),
        "vs_currencies": "usd"
    }

    try:
        response = requests.get(COINGECKO_API, params=params, timeout=5)
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print("API error:", e)
        return {}


@app.route("/")
def index():
    search = request.args.get("search")
    prices = fetch_prices()

    if search:
        prices = {
            coin: data
            for coin, data in prices.items()
            if search.lower() in coin.lower()
        }

    return render_template("index.html", prices=prices)

@app.route("/coin/<coin_id>")
def coin_detail(coin_id):

    if coin_id not in CRYPTO_COINS:
        return "Coin not supported", 404

    HEADERS = {
        "User-Agent": "CryptoPriceTracker/1.0"
    }

    coin_url = f"https://api.coingecko.com/api/v3/coins/{coin_id}"
    chart_url = f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart"

    coin_data = requests.get(coin_url, headers=HEADERS).json()

    chart_data = requests.get(
        chart_url,
        params={"vs_currency": "usd", "days": 365},
        headers=HEADERS,
        timeout=10
    ).json()

    prices = chart_data.get("prices", [])

    from collections import defaultdict
    month_prices = defaultdict(list)

    for timestamp, price in prices:
        if isinstance(price, (int, float)):
            month = datetime.fromtimestamp(timestamp / 1000).strftime("%b %Y")
            month_prices[month].append(price)

    labels = list(month_prices.keys())
    values = [
        round(sum(p) / len(p), 2)
        for p in month_prices.values()
    ]

    return render_template(
        "coin.html",
        coin=coin_data,
        labels=labels,
        values=values
    )




from flask import Flask, render_template, request, redirect, url_for

# existing app setup stays same

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # later: validate user (DynamoDB / Cognito)
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # later: create user (DynamoDB / Cognito)
        return redirect(url_for("login"))

    return render_template("signup.html")

if __name__ == "__main__":
      app.run(debug=True)

