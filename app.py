from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import requests
import socket
import time
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import json
import boto3

load_dotenv()

# ================= CONFIG =================

ADMIN_CONFIG_FILE = "admin_config.json"
USERS_FILE = "users.json"
ALERTS_FILE = "alerts.json"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

def load_json_file(filename, default):
    if os.path.exists(filename):
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
    return default

def save_json_file(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving {filename}: {e}")

def load_admin_config():
    global ADMIN_USERNAME, ADMIN_PASSWORD
    data = load_json_file(ADMIN_CONFIG_FILE, {})
    ADMIN_USERNAME = data.get("username", ADMIN_USERNAME)
    ADMIN_PASSWORD = data.get("password", ADMIN_PASSWORD)

load_admin_config()

# Load users from disk
users = load_json_file(USERS_FILE, [])
alerts = load_json_file(ALERTS_FILE, [])

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_key_for_crypto_app")  # Required for session

COINGECKO_API = "https://api.coingecko.com/api/v3/simple/price"
TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"

socket._orig_getaddrinfo = socket.getaddrinfo

LAST_TOP_COINS = []
LAST_GOOD_PRICES = {}
LAST_FETCH_TIME = 0
CACHE_DURATION = 60  # Cache prices for 60 seconds

# Users and Alerts loaded via load_json_file above
# users = [] (Removed, now persistent)
# ALERTS = [] (Removed, now persistent)

LAST_CHART_DATA = {}
import time
import threading
import requests

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "CryptoPriceTracker/1.0"
})

api_key = os.getenv("COINGECKO_API_KEY")
if api_key:
    # Check if it is a Pro key or Demo key based on prefix if needed, 
    # but usually x-cg-demo-api-key works for the demo plan keys (CG-...)
    # and x-cg-pro-api-key for Pro keys.
    # The user provided a key starting with CG-, which is likely a demo key.
    header_name = "x-cg-demo-api-key" if api_key.startswith("CG-") else "x-cg-pro-api-key"
    SESSION.headers.update({
        header_name: api_key
    })

API_LOCK = threading.Lock()
LAST_API_CALL = 0
MIN_API_INTERVAL = 1.5   # Reduced to 1.5s with API key


def fetch_top_10_coins():
    global LAST_TOP_COINS
    try:
        r = safe_get(
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

def safe_get(url, params=None, timeout=10):
    global LAST_API_CALL

    retries = 3
    backoff = 2

    for i in range(retries):
        with API_LOCK:
            now = time.time()
            wait = MIN_API_INTERVAL - (now - LAST_API_CALL)
            if wait > 0:
                time.sleep(wait)
            LAST_API_CALL = time.time()

        response = SESSION.get(url, params=params, timeout=timeout)
        
        if response.status_code == 429:
            print(f"Rate limited (429). Retrying in {backoff}s...")
            time.sleep(backoff)
            backoff *= 2  # Exponential backoff
            continue
            
        return response

    return response  # Return last response even if 429

def is_valid_coin(data):
    try:
        md = data["market_data"]
        return (
            md
            and md["current_price"]["usd"] is not None
            and md["market_cap"]["usd"] is not None
        )
    except Exception:
        return False


def search_any_coin(query):
    try:
        r = safe_get(SEARCH_API, params={"query": query}, timeout=8)
        r.raise_for_status()
        return r.json().get("coins", [])
    except Exception as e:
        print("Search error:", e)
        return []
def fetch_prices_for_coins(coins):
    global LAST_GOOD_PRICES
    if not coins:
        return {}

    # Check if we have recent data for all coins
    # Simple strategy: if we have cached data for these coins and it's fresh enough?
    # For now, just rely on try/except fallback
    
    try:
        r = safe_get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={
                "ids": ",".join(coins),
                "vs_currencies": "usd"
            },
            timeout=6
        )
        r.raise_for_status()
        data = r.json()
        
        # Update cache with new data
        if data:
            for k, v in data.items():
                LAST_GOOD_PRICES[k] = v
                
        return data
    except Exception as e:
        print(f"Price fetch failed: {e}")
        # Return whatever we have in cache for the requested coins
        return {k: v for k, v in LAST_GOOD_PRICES.items() if k in coins}

import time

COIN_CACHE = {}
CHART_CACHE = {}
CACHE_TTL = 300  # seconds

def get_cached_coin(coin_id):
    entry = COIN_CACHE.get(coin_id)
    if entry and entry["expires"] > time.time():
        return entry["data"]
    return None

def set_cached_coin(coin_id, data):
    COIN_CACHE[coin_id] = {
        "data": data,
        "expires": time.time() + CACHE_TTL
    }


@app.route("/", methods=["GET"])
def index():
    top_coins = fetch_top_10_coins()

    return render_template(
        "index.html",
        top_coins=top_coins,
        search_results=[]   
    )


@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("search", "").strip()

    top_coins = fetch_top_10_coins()  
    search_results = []

    if query:
        search_results = search_any_coin(query)

    return render_template(
        "index.html",
        top_coins=top_coins,
        search_results=search_results
    )



def get_cached_chart(coin_id):
    entry = CHART_CACHE.get(coin_id)
    if entry and entry["expires"] > time.time():
        return entry["labels"], entry["values"]
    return None, None

def set_cached_chart(coin_id, labels, values):
    CHART_CACHE[coin_id] = {
        "labels": labels,
        "values": values,
        "expires": time.time() + CACHE_TTL
    }


@app.route("/coin/<coin_id>")
def coin_detail(coin_id):

    fallback = get_cached_coin(coin_id)

    coin = fallback or {
        "id": coin_id,
        "name": coin_id.replace("-", " ").title(),
        "symbol": coin_id[:4].upper(),
        "market_cap_rank": None,
        "market_data": None
    }


    # ---------- FETCH COIN DATA ----------
    # If we have valid cached data, USE IT and skip the API call
    # This prevents hitting rate limits when navigating back and forth
    if not fallback:
        try:
           r = safe_get(f"https://api.coingecko.com/api/v3/coins/{coin_id}")

           if r.status_code == 200:
            data = r.json()

            if is_valid_coin(data):
                coin = data
                set_cached_coin(coin_id, data)
           elif r.status_code == 429:
               print("Rate limited on coin detail")

        except Exception as e:
                 print("Coin API failed → using cache:", e)

    
    # ---------- CHART ----------
    labels, values = get_cached_chart(coin_id)
    
    if not labels:
        labels, values = [], []
        try:
            r = safe_get(
                f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart",
                params={"vs_currency": "usd", "days": 365}
            )

            if r.status_code == 200:
                prices = r.json().get("prices", [])
                if prices:
                    from collections import OrderedDict
                    monthly = OrderedDict()
                    for ts, price in prices:
                        month = datetime.fromtimestamp(ts/1000).strftime("%b %Y")
                        monthly.setdefault(month, []).append(price)

                    labels = list(monthly.keys())
                    values = [round(sum(v)/len(v), 2) for v in monthly.values()]
                    
                    set_cached_chart(coin_id, labels, values)

        except Exception as e:
            print("Chart API failed:", e)

    is_favorite = coin_id in session.get("favorites", [])

    return render_template(
        "coin.html",
        coin=coin,
        labels=labels,
        values=values,
        is_favorite=is_favorite
    )




@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        if not email or "@" not in email:
             return render_template("signup.html", error="Invalid email address")

        users.append({
            "username": request.form["username"],
            "email": email,
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        save_json_file(USERS_FILE, users)

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
    # Allow anonymous favorites (stored in session)
    # if "user" not in session:
    #    return redirect(url_for("login"))

    favorite_coins = session.get("favorites", [])
    prices = fetch_prices_for_coins(favorite_coins)

    return render_template(
        "favorites.html",
        prices=prices,
        favorite_coins=favorite_coins
    )
@app.route("/add_favorite/<coin_id>")
def add_favorite(coin_id):
    session.setdefault("favorites", [])
    if coin_id not in session["favorites"]:
        session["favorites"].append(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/remove_favorite/<coin_id>", methods=["GET", "POST"])
def remove_favorite(coin_id):
    if "favorites" in session and coin_id in session["favorites"]:
        session["favorites"].remove(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/set_alert", methods=["POST"])
def set_alert():
    if "user" not in session:
        return redirect(url_for("login"))

    coin = request.form.get("coin")
    threshold = request.form.get("threshold")
    
    # Find user email
    user_email = ""
    for u in users:
        if u["username"] == session["user"]:
            user_email = u.get("email", "")
            break

    if coin and threshold:
        try:
            alerts.append({
                "user": session["user"],
                "email": user_email,
                "coin": coin,
                "threshold": float(threshold),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            save_json_file(ALERTS_FILE, alerts)
        except ValueError:
            pass

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

@app.route("/admin/update_credentials", methods=["POST"])
def update_credentials():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    
    new_username = request.form.get("new_username", "").strip()
    new_password = request.form.get("new_password", "").strip()
    
    global ADMIN_USERNAME, ADMIN_PASSWORD
    
    changed = False
    if new_username:
        ADMIN_USERNAME = new_username
        changed = True
    
    if new_password:
        ADMIN_PASSWORD = new_password
        changed = True
    
    if changed:
        try:
            with open(ADMIN_CONFIG_FILE, "w") as f:
                json.dump({
                    "username": ADMIN_USERNAME,
                    "password": ADMIN_PASSWORD
                }, f)
        except Exception as e:
            print(f"Error saving admin config: {e}")
    
    return redirect(url_for("admin_dashboard"))

def init_aws_resources():
    region = os.getenv("AWS_REGION", "us-east-1")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    sns = boto3.client("sns", region_name=region)
    try:
        dynamodb.meta.client.describe_table(TableName="Users")
        table = dynamodb.Table("Users")
    except Exception:
        t = dynamodb.create_table(
            TableName="Users",
            KeySchema=[{"AttributeName": "username", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "username", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST"
        )
        t.wait_until_exists()
        table = t
    topic_arn = sns.create_topic(Name="CryptoPriceAlerts")["TopicArn"]
    return table, topic_arn


 

def check_alerts_background():
    while True:
        try:
            unique_coins = list({a["coin"] for a in alerts})
            if unique_coins:
                prices = fetch_prices_for_coins(unique_coins)
                now = time.time()
                
                for a in alerts:
                    coin = a["coin"]
                    threshold = float(a["threshold"])
                    last_alert_time = float(a.get("cooldown", 0))
                    
                    current_price_data = prices.get(coin)
                    if current_price_data:
                        current_price = current_price_data.get("usd")
                        
                        # Alert if price is below threshold (Dip Alert)
                        if current_price is not None and current_price < threshold:
                            if (now - last_alert_time) > 3600: # 1 hour cooldown
                                print(f"🔔 [ALERT] {coin.title()} price ${current_price} is below ${threshold}")
                                a["cooldown"] = str(now)
                                save_json_file(ALERTS_FILE, alerts)

        except Exception as e:
            print(f"Error in alert background task: {e}")
            
        time.sleep(60)

# ================= RUN =================

if __name__ == "__main__":
    threading.Thread(target=check_alerts_background, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
