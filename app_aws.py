from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
import json
import time
import threading

import os

# ================== CONFIG ==================

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

REGION = os.getenv("AWS_REGION", "us-east-1")
USERS_TABLE = "Users"
SNS_TOPIC_NAME = "user-events"
ALERTS_TABLE = "Alerts"

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super_secret_key_for_crypto_app")

# ================== AWS CLIENTS ==================

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

def ensure_table(name, key_schema, attr_defs):
    try:
        dynamodb.meta.client.describe_table(TableName=name)
    except Exception:
        t = dynamodb.create_table(
            TableName=name,
            KeySchema=key_schema,
            AttributeDefinitions=attr_defs,
            BillingMode="PAY_PER_REQUEST"
        )
        t.wait_until_exists()
    return dynamodb.Table(name)

users_table = ensure_table(
    USERS_TABLE,
    [{"AttributeName": "username", "KeyType": "HASH"}],
    [{"AttributeName": "username", "AttributeType": "S"}]
)
alerts_table = ensure_table(
    ALERTS_TABLE,
    [{"AttributeName": "alert_id", "KeyType": "HASH"}],
    [{"AttributeName": "alert_id", "AttributeType": "S"}]
)

# Fetch SNS topic ARN
TOPIC_ARN = None
try:
    topics = sns.list_topics()["Topics"]
    TOPIC_ARN = next(t["TopicArn"] for t in topics if SNS_TOPIC_NAME in t["TopicArn"])
except Exception:
    pass
if not TOPIC_ARN:
    TOPIC_ARN = sns.create_topic(Name=SNS_TOPIC_NAME)["TopicArn"]

# ================== COINGECKO ==================

TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"

# ================== HELPERS ==================

def fetch_top_10_coins():
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
        return r.json()
    except:
        return []

def search_any_coin(query):
    try:
        r = requests.get(
            SEARCH_API,
            params={"query": query},
            timeout=8
        )
        r.raise_for_status()
        return r.json().get("coins", [])
    except:
        return []

def fetch_prices_for_coins(coins):
    if not coins:
        return {}
    r = requests.get(
        "https://api.coingecko.com/api/v3/simple/price",
        params={"ids": ",".join(coins), "vs_currencies": "usd"},
        timeout=8
    )
    r.raise_for_status()
    return r.json()

def check_alerts_background():
    while True:
        try:
            res = alerts_table.scan()
            alerts = res.get("Items", [])
            coins = list({a["coin"] for a in alerts})
            prices = fetch_prices_for_coins(coins) if coins else {}
            now = time.time()
            for a in alerts:
                coin = a["coin"]
                threshold = float(a["threshold"])
                email = a["email"]
                last = float(a.get("cooldown", 0))
                price = prices.get(coin, {}).get("usd")
                if price is not None and price < threshold and now - last > 3600:
                    msg = f"{coin.title()} price ${price} is below ${threshold}"
                    sns.publish(
                        TopicArn=TOPIC_ARN,
                        Message=msg,
                        Subject=f"Price Alert: {coin.title()}",
                        MessageAttributes={
                            "email": {"DataType": "String", "StringValue": email}
                        }
                    )
                    alerts_table.update_item(
                        Key={"alert_id": a["alert_id"]},
                        UpdateExpression="SET cooldown = :c",
                        ExpressionAttributeValues={":c": str(now)}
                    )
        except:
            pass
        time.sleep(60)

# ================== ROUTES ==================

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
    coin = requests.get(
        f"https://api.coingecko.com/api/v3/coins/{coin_id}",
        timeout=10
    ).json()

    chart = requests.get(
        f"https://api.coingecko.com/api/v3/coins/{coin_id}/market_chart",
        params={"vs_currency": "usd", "days": 365},
        timeout=10
    ).json()

    prices = chart.get("prices", [])

    from collections import defaultdict
    monthly = defaultdict(list)

    for ts, price in prices:
        month = datetime.fromtimestamp(ts / 1000).strftime("%b %Y")
        monthly[month].append(price)

    labels = list(monthly.keys())
    values = [round(sum(v) / len(v), 2) for v in monthly.values()]

    return render_template(
        "coin.html",
        coin=coin,
        labels=labels,
        values=values,
        is_favorite=coin_id in session.get("favorites", [])
    )

# ================== AUTH (DYNAMODB) ==================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        user = {
            "username": request.form["username"],
            "email": request.form["email"],
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.utcnow().isoformat()
        }

        users_table.put_item(Item=user)

        try:
            sns.subscribe(
                TopicArn=TOPIC_ARN,
                Protocol="email",
                Endpoint=user["email"],
                Attributes={"FilterPolicy": json.dumps({"email": [user["email"]]})}
            )
        except:
            pass

        return redirect(url_for("login"))

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

# ================== FAVORITES ==================

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
    if "user" not in session:
        return redirect(url_for("login"))
    res = users_table.get_item(Key={"username": session["user"]})
    user = res.get("Item")
    if not user or not user.get("email"):
        return redirect(url_for("favorites"))
    coin = request.form.get("coin")
    threshold = request.form.get("threshold")
    if coin and threshold:
        try:
            tid = f"{user['email']}#{coin}"
            alerts_table.put_item(
                Item={
                    "alert_id": tid,
                    "email": user["email"],
                    "coin": coin,
                    "threshold": str(float(threshold)),
                    "cooldown": "0"
                }
            )
        except:
            pass
    return redirect(url_for("favorites"))

# ================== ADMIN ==================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USERNAME and
            request.form["password"] == ADMIN_PASSWORD
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

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

# ================== RUN ==================

if __name__ == "__main__":
    threading.Thread(target=check_alerts_background, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
