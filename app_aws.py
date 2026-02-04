from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
import time
import threading
import os
from dotenv import load_dotenv

load_dotenv()

# ================== CONFIG ==================

# Admin credentials stored in DynamoDB (AdminConfig table)

REGION = "us-east-1"
USERS_TABLE = "Users"
ALERTS_TABLE = "Alerts"
ADMIN_CONFIG_TABLE = "AdminConfig"
SNS_TOPIC_NAME = "CryptoPriceAlerts"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_key_for_crypto_app")

# ================== AWS CLIENTS ==================

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table(USERS_TABLE)
alerts_table = dynamodb.Table(ALERTS_TABLE)
admin_config_table = dynamodb.Table(ADMIN_CONFIG_TABLE)

# Check if Admin Config table exists, if not, create it
try:
    dynamodb.meta.client.describe_table(TableName=ADMIN_CONFIG_TABLE)
except Exception:
    try:
        table = dynamodb.create_table(
            TableName=ADMIN_CONFIG_TABLE,
            KeySchema=[
                {"AttributeName": "config_id", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "config_id", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()
        print("Created AdminConfig table")
        
        # Initialize with default credentials
        admin_config_table.put_item(Item={
            "config_id": "main",
            "username": "admin",
            "password": "admin123"
        })
    except Exception as e:
        print(f"Failed to create AdminConfig table: {e}")

# Check if Alerts table exists, if not, create it (Simplified check)
try:
    dynamodb.meta.client.describe_table(TableName=ALERTS_TABLE)
except Exception:
    try:
        table = dynamodb.create_table(
            TableName=ALERTS_TABLE,
            KeySchema=[
                {"AttributeName": "email", "KeyType": "HASH"},
                {"AttributeName": "coin", "KeyType": "RANGE"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "email", "AttributeType": "S"},
                {"AttributeName": "coin", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST"
        )
        table.wait_until_exists()
        print("Created Alerts table")
    except Exception as e:
        print(f"Failed to create Alerts table: {e}")
        
# ... SNS Init ...
try:
    topics = sns.list_topics()["Topics"]
    TOPIC_ARN = next(
        (t["TopicArn"] for t in topics if SNS_TOPIC_NAME in t["TopicArn"]), None
    )
    if not TOPIC_ARN:
        topic = sns.create_topic(Name=SNS_TOPIC_NAME)
        TOPIC_ARN = topic["TopicArn"]
    print(f"Using SNS Topic: {TOPIC_ARN}")
except Exception as e:
    print(f"SNS Init Error: {e}")
    TOPIC_ARN = None


TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"

API_LOCK = threading.Lock()
LAST_API_CALL = 0
MIN_API_INTERVAL = 1.5
SESSION = requests.Session()

api_key = os.getenv("COINGECKO_API_KEY")
if api_key:
    header_name = "x-cg-demo-api-key" if api_key.startswith("CG-") else "x-cg-pro-api-key"
    SESSION.headers.update({header_name: api_key})

COIN_CACHE = {}
CHART_CACHE = {}
CACHE_TTL = 300

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
            backoff *= 2
            continue
            
        return response

    return response



def fetch_top_10_coins():
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
        return r.json()
    except Exception as e:
        print(f"Top coins error: {e}")
        return []

def search_any_coin(query):
    try:
        r = safe_get(
            SEARCH_API,
            params={"query": query},
            timeout=8
        )
        r.raise_for_status()
        return r.json().get("coins", [])
    except:
        return []

def fetch_prices_for_coins(coins):
    if not coins: return {}
    try:
        r = safe_get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": ",".join(coins), "vs_currencies": "usd"},
            timeout=6
        )
        r.raise_for_status()
        return r.json()
    except:
        return {}



def check_alerts_background():
    while True:
        try:
            if TOPIC_ARN:
                
                scan = alerts_table.scan()
                alerts = scan.get("Items", [])
                
                if alerts:
                    coins_to_check = list(set(a["coin"] for a in alerts))
                    if coins_to_check:
                        prices = fetch_prices_for_coins(coins_to_check)
                        now = time.time()
                        
                        for alert in alerts:
                            coin = alert["coin"]
                            threshold = float(alert["threshold"]) 
                            email = alert["email"]
                            cooldown = float(alert.get("cooldown", 0))
                            
                            if coin in prices and "usd" in prices[coin]:
                                current_price = prices[coin]["usd"]
                                if current_price < threshold:
                                    if now - cooldown > 3600:
                                        message = (
                                            f"Price Alert: {coin.title()} has dropped below ${threshold}!\n"
                                            f"Current Price: ${current_price}\n"
                                        )
                                        try:
                                            sns.publish(
                                                TopicArn=TOPIC_ARN,
                                                Message=message,
                                                Subject=f"Price Alert: {coin.title()}",
                                                MessageAttributes={
                                                    "email": {"DataType": "String", "StringValue": email}
                                                }
                                            )
                                            print(f"Alert sent to {email}")
                                            
                                            
                                            alerts_table.update_item(
                                                Key={"email": email, "coin": coin},
                                                UpdateExpression="set cooldown = :c",
                                                ExpressionAttributeValues={":c": int(now)}
                                            )
                                        except Exception as e:
                                            print(f"Failed to publish SNS: {e}")

            time.sleep(60)
        except Exception as e:
            print(f"Alert check failed: {e}")
            time.sleep(60)

threading.Thread(target=check_alerts_background, daemon=True).start()



@app.route("/")
def index():
    return render_template(
        "index.html",
        top_coins=fetch_top_10_coins(),
        search_results=[]
    )

@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("search", "")
    return render_template(
        "index.html",
        top_coins=fetch_top_10_coins(),
        search_results=search_any_coin(query)
    )

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
    
    if not fallback:
        try:
            r = safe_get(f"https://api.coingecko.com/api/v3/coins/{coin_id}")
            if r.status_code == 200:
                data = r.json()
                coin = data
                set_cached_coin(coin_id, data)
        except:
            pass

    labels, values = get_cached_chart(coin_id)
    if not labels:
        try:
            r = safe_get(
                f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart",
                params={"vs_currency": "usd", "days": 365}
            )
            if r.status_code == 200:
                prices = r.json().get("prices", [])
                if prices:
                    from collections import defaultdict
                    monthly = defaultdict(list)
                    for ts, price in prices:
                        month = datetime.fromtimestamp(ts / 1000).strftime("%b %Y")
                        monthly[month].append(price)
                    labels = list(monthly.keys())
                    values = [round(sum(v) / len(v), 2) for v in monthly.values()]
                    set_cached_chart(coin_id, labels, values)
        except:
            labels, values = [], []

    return render_template(
        "coin.html",
        coin=coin,
        labels=labels,
        values=values,
        is_favorite=coin_id in session.get("favorites", [])
    )



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        user = {
            "username": request.form["username"],
            "email": email,
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.utcnow().isoformat()
        }

        try:
            users_table.put_item(Item=user)
            
            # Subscribe to SNS
            if TOPIC_ARN:
                sns.subscribe(
                    TopicArn=TOPIC_ARN,
                    Protocol="email",
                    Endpoint=email,
                    Attributes={"FilterPolicy": f'{{"email": ["{email}"]}}'}
                )

            return redirect(url_for("login"))
        except Exception as e:
            return render_template("signup.html", error=f"Error: {e}")

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        res = users_table.get_item(
            Key={"username": request.form["username"]}
        )

        user = res.get("Item")
        if user and check_password_hash(
            user["password"],
            request.form["password"]
        ):
            session["user"] = user["username"]
            return redirect(url_for("index"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))



@app.route("/favorites")
def favorites():
    favorite_coins = session.get("favorites", [])
    prices = fetch_prices_for_coins(favorite_coins)
    return render_template("favorites.html", prices=prices, favorite_coins=favorite_coins)

@app.route("/add_favorite/<coin_id>")
def add_favorite(coin_id):
    session.setdefault("favorites", [])
    if coin_id not in session["favorites"]:
        session["favorites"].append(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/remove_favorite/<coin_id>")
def remove_favorite(coin_id):
    if "favorites" in session and coin_id in session["favorites"]:
        session["favorites"].remove(coin_id)
        session.modified = True
    return redirect(url_for("favorites"))

@app.route("/set_alert", methods=["POST"])
def set_alert():
    if "user" not in session: return redirect(url_for("login"))
    
  
    res = users_table.get_item(Key={"username": session["user"]})
    user = res.get("Item")
    if not user or "email" not in user:
        return redirect(url_for("favorites"))
        
    coin = request.form.get("coin")
    threshold = request.form.get("threshold")
    
    if coin and threshold:
        try:
            threshold_val = str(float(threshold)) 
            alerts_table.put_item(Item={
                "email": user["email"],
                "coin": coin,
                "threshold": threshold_val,
                "cooldown": 0
            })
            print(f"Alert set for {user['email']}: {coin} < {threshold}")
        except Exception as e:
            print(f"Set alert error: {e}")
            pass
            
    return redirect(url_for("favorites"))


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        # Fetch current credentials from DB
        current_username = "admin"
        current_password = "admin123"
        try:
            res = admin_config_table.get_item(Key={"config_id": "main"})
            if "Item" in res:
                current_username = res["Item"].get("username", "admin")
                current_password = res["Item"].get("password", "admin123")
        except Exception as e:
            print(f"Error fetching admin creds: {e}")

        if (
            request.form["username"] == current_username and
            request.form["password"] == current_password
        ):
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))

        return render_template("admin.html", error="Invalid credentials")

    return render_template("admin.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    scan = users_table.scan()
    users = scan.get("Items", [])

    return render_template(
        "admin.html",
        users=users,
        total_users=len(users)
    )

@app.route("/admin/update_credentials", methods=["POST"])
def update_credentials():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
        
    new_username = request.form.get("new_username", "").strip()
    new_password = request.form.get("new_password", "").strip()
    
    if new_username or new_password:
        try:
            # First get current to preserve what's not changing
            res = admin_config_table.get_item(Key={"config_id": "main"})
            item = res.get("Item", {"config_id": "main", "username": "admin", "password": "admin123"})
            
            if new_username:
                item["username"] = new_username
            if new_password:
                item["password"] = new_password
                
            admin_config_table.put_item(Item=item)
            print("Admin credentials updated")
        except Exception as e:
            print(f"Error updating admin creds: {e}")
            
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
