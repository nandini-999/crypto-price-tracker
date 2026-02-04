from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import socket
from werkzeug.security import generate_password_hash, check_password_hash

# ================= CONFIG =================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

app = Flask(__name__)
app.secret_key = "super_secret_key_for_crypto_app"

COINGECKO_API = "https://api.coingecko.com/api/v3/simple/price"
TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"

socket._orig_getaddrinfo = socket.getaddrinfo

LAST_TOP_COINS = []
LAST_GOOD_PRICES = []
users = []


# ================= DATA FETCH =================
LAST_CHART_DATA = {}


def fetch_top_10_coins():
    global LAST_TOP_COINS
    try:
        r = requests.get(
            TOP_COINS_API,
            params={
                "vs_currency": "usd",
                "order": "market_cap_desc",
                "per_page": 10,
                "page": 1
            },
            timeout=8
        )
        r.raise_for_status()
        data = r.json()
        if data:
            LAST_TOP_COINS = data
        return LAST_TOP_COINS
    except Exception as e:
        print("Top coins error:", e)
        return LAST_TOP_COINS


def search_any_coin(query):
    try:
        r = requests.get(SEARCH_API, params={"query": query}, timeout=8)
        r.raise_for_status()
        return r.json().get("coins", [])
    except Exception as e:
        print("Search error:", e)
        return []
def fetch_prices_for_coins(coins):
    if not coins:
        return {}

    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={
                "ids": ",".join(coins),
                "vs_currencies": "usd"
            },
            timeout=6
        )
        r.raise_for_status()
        return r.json()
    except:
        return {}

import time

COIN_CACHE = {}
CHART_CACHE = {}
CACHE_TTL = 300  # seconds

def get_cached(cache, key):
    entry = cache.get(key)
    if entry and entry["expires"] > time.time():
        return entry["data"]
    return None

def set_cache(cache, key, data):
    cache[key] = {
        "data": data,
        "expires": time.time() + CACHE_TTL
    }


# ================= ROUTES =================

@app.route("/", methods=["GET"])
def index():
    top_coins = fetch_top_10_coins()

    return render_template(
        "index.html",
        top_coins=top_coins,
        search_results=[]   # ✅ ALWAYS an empty list
    )


@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("search", "").strip()

    top_coins = fetch_top_10_coins()  # ✅ still loaded
    search_results = []

    if query:
        search_results = search_any_coin(query)

    return render_template(
        "index.html",
        top_coins=top_coins,
        search_results=search_results
    )



@app.route("/coin/<coin_id>")
def coin_detail(coin_id):
    HEADERS = {"User-Agent": "CryptoPriceTracker/1.0"}

    # ---------- SAFE DEFAULT ----------
    coin = {
        "id": coin_id,
        "name": coin_id.replace("-", " ").title(),
        "symbol": "",
        "market_cap_rank": "N/A",
        "market_data": None
    }

    labels, values = [], []

    # ---------- COIN DATA ----------
    cached = get_cached(COIN_CACHE, coin_id)
    if cached:
        coin = cached
    else:
        try:
            time.sleep(1)  # ✅ avoid rate-limit

            r = requests.get(
                f"https://api.coingecko.com/api/v3/coins/{coin_id}",
                headers=HEADERS,
                timeout=10
            )

            if r.status_code == 200:
                data = r.json()

                # ✅ ONLY CACHE VALID DATA
                if data.get("market_data"):
                    coin = data
                    set_cache(COIN_CACHE, coin_id, data)

        except Exception as e:
            print("Coin fetch failed:", e)

    # ---------- CHART ----------
    cached_chart = get_cached(CHART_CACHE, coin_id)
    if cached_chart:
        labels, values = cached_chart
    else:
        try:
            time.sleep(1)

            r = requests.get(
                f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart",
                params={"vs_currency": "usd", "days": 365},
                headers=HEADERS,
                timeout=10
            )

            if r.status_code == 200:
                prices = r.json().get("prices", [])

                if prices:
                    from collections import OrderedDict
                    monthly = OrderedDict()

                    for ts, price in prices:
                        month = datetime.fromtimestamp(
                            ts / 1000
                        ).strftime("%b %Y")
                        monthly.setdefault(month, []).append(price)

                    labels = list(monthly.keys())
                    values = [round(sum(v)/len(v), 2) for v in monthly.values()]

                    set_cache(CHART_CACHE, coin_id, (labels, values))

        except Exception as e:
            print("Chart fetch failed:", e)

    is_favorite = coin_id in session.get("favorites", [])

    return render_template(
        "coin.html",
        coin=coin,
        labels=labels,
        values=values,
        is_favorite=is_favorite
    )
import boto3
def init_aws_resources():
    dynamodb = boto3.resource(
        "dynamodb",
        region_name="us-east-1"
    )

    sns = boto3.client(
        "sns",
        region_name="us-east-1"
    )

    # Create DynamoDB table
    table = dynamodb.create_table(
        TableName="Users",
        KeySchema=[
            {"AttributeName": "username", "KeyType": "HASH"}
        ],
        AttributeDefinitions=[
            {"AttributeName": "username", "AttributeType": "S"}
        ],
        BillingMode="PAY_PER_REQUEST"
    )

    # Create SNS topic
    topic = sns.create_topic(Name="user-events")

    return table, topic["TopicArn"]

# ================= AUTH =================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        users.append({
            "username": request.form["username"],
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        for u in users:
            if u["username"] == request.form["username"] and \
               check_password_hash(u["password"], request.form["password"]):
                session["user"] = u["username"]
                return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
@app.route("/favorites")
def favorites():
    if "user" not in session:
        return redirect(url_for("login"))

    favorite_coins = session.get("favorites", [])
    prices = fetch_prices_for_coins(favorite_coins)

    return render_template(
        "favorites.html",
        prices=prices
    )
@app.route("/add_favorite/<coin_id>")
def add_favorite(coin_id):
    session.setdefault("favorites", [])
    if coin_id not in session["favorites"]:
        session["favorites"].append(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

# ================= ADMIN =================
# ================= ADMIN =================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USERNAME and
            request.form["password"] == ADMIN_PASSWORD
        ):
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))

        return render_template(
            "admin_login.html",
            error="Invalid admin credentials"
        )

    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    return render_template(
        "admin.html",     # ✅ IMPORTANT
        users=users,
        total_users=len(users)
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

# ================= RUN =================

if __name__ == "__main__":
    app.run(debug=True)
