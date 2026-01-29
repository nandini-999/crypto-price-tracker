from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import socket
from werkzeug.security import generate_password_hash, check_password_hash
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # change later

app = Flask(__name__)
app.secret_key = "super_secret_key_for_crypto_app"  # Required for session
LAST_GOOD_PRICES = {}
USERS_DB={}
users = []
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
    global LAST_GOOD_PRICES

    params = {
        "ids": ",".join(CRYPTO_COINS),
        "vs_currencies": "usd"
    }

    try:
        response = requests.get(
            COINGECKO_API,
            params=params,
            timeout=5
        )
        response.raise_for_status()

        data = response.json()

        # ✅ Save good data
        if data:
            LAST_GOOD_PRICES = data

        return data

    except requests.exceptions.RequestException as e:
        print("API error:", e)

        # ✅ Fallback to last good data
        return LAST_GOOD_PRICES

from flask import session, redirect, url_for

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))

        return render_template("admin_login.html", error="Invalid credentials")

    return render_template("admin_login.html")

def admin_required():
    return session.get("is_admin")

from flask import make_response
@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    return render_template(
        "admin.html",
        total_users=len(users),
        users=users
    )

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("index"))

@app.route("/", methods=["GET", "POST"])
def index():
    prices = fetch_prices()

    if request.method == "POST":
        search = request.form.get("search", "").strip()

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

    is_favorite = False
    if "favorites" in session:
        if coin_id in session["favorites"]:
            is_favorite = True

    return render_template(
        "coin.html",
        coin=coin_data,
        labels=labels,
        values=values,
        is_favorite=is_favorite
    )




from flask import Flask, render_template, request, redirect, url_for

# existing app setup stays same



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Check duplicate username
        for u in users:
            if u["username"] == username:
                return render_template(
                    "signup.html",
                    error="Username already exists"
                )

        hashed_password = generate_password_hash(password)

        users.append({
            "username": username,
            "email": email,
            "password": hashed_password,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        for u in users:
            if u["username"] == username and check_password_hash(u["password"], password):
                session["user"] = username
                return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")



@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/favorites")
def favorites():
    favorites_list = session.get("favorites", [])
    all_prices = fetch_prices()
    
    # Filter prices for only favorite coins
    fav_prices = {
        coin: data 
        for coin, data in all_prices.items() 
        if coin in favorites_list
    }
    
    return render_template("favorites.html", prices=fav_prices)


@app.route("/add_favorite/<coin_id>")
def add_favorite(coin_id):
    if "favorites" not in session:
        session["favorites"] = []
    
    favorites = session["favorites"]
    if coin_id not in favorites and coin_id in CRYPTO_COINS:
        favorites.append(coin_id)
        session.modified = True
        
    return redirect(url_for("favorites"))


@app.route("/remove_favorite/<coin_id>")
def remove_favorite(coin_id):
    if "favorites" in session:
        favorites = session["favorites"]
        if coin_id in favorites:
            favorites.remove(coin_id)
            session.modified = True
            
    return redirect(url_for("favorites"))


if __name__ == "__main__":
      app.run(debug=True)