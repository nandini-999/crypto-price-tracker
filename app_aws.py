from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import requests
import time
import threading
import os
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from boto3.dynamodb.conditions import Key

# ================= CONFIG =================

REGION = "us-east-1"
TOPIC_ARN = "arn:aws:sns:us-east-1:216989138822:aws_capstone_topic"

app = Flask(__name__)
app.secret_key = "super_secret_key"

# ================= AWS =================

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table("Users")
favorites_table = dynamodb.Table("Favorites")
alerts_table = dynamodb.Table("Alerts")

# ================= COINGECKO =================

TOP_COINS_API = "https://api.coingecko.com/api/v3/coins/markets"
SEARCH_API = "https://api.coingecko.com/api/v3/search"

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
            timeout=10
        )
        return r.json()
    except:
        return []

def search_any_coin(query):
    try:
        r = requests.get(SEARCH_API, params={"query": query}, timeout=10)
        return r.json().get("coins", [])
    except:
        return []

def fetch_prices_for_coins(coins):
    if not coins:
        return {}
    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": ",".join(coins), "vs_currencies": "usd"},
            timeout=10
        )
        return r.json()
    except:
        return {}

# ================= ALERT CHECKER =================

def check_alerts_background():
    while True:
        try:
            res = alerts_table.scan()
            alerts = res.get("Items", [])
            coins = list({a["coin"] for a in alerts})
            prices = fetch_prices_for_coins(coins)
            now = time.time()

            for a in alerts:
                coin = a["coin"]
                threshold = float(a["threshold"])
                email = a["email"]
                last = float(a.get("cooldown", 0))

                price = prices.get(coin, {}).get("usd")

                if price and price < threshold and now - last > 3600:
                    msg = f"{coin.title()} price ${price} below ${threshold}"

                    sns.publish(
                        TopicArn=TOPIC_ARN,
                        Message=msg,
                        Subject="Crypto Alert"
                    )

                    alerts_table.update_item(
                        Key={"alert_id": a["alert_id"]},
                        UpdateExpression="SET cooldown = :c",
                        ExpressionAttributeValues={":c": str(now)}
                    )
        except:
            pass

        time.sleep(60)

# ================= ROUTES =================

@app.route("/")
def index():
    return render_template(
        "index.html",
        top_coins=fetch_top_10_coins(),
        search_results=[]
    )

@app.route("/search", methods=["POST"])
def search():
    q = request.form.get("search")
    return render_template(
        "index.html",
        top_coins=fetch_top_10_coins(),
        search_results=search_any_coin(q)
    )

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        users_table.put_item(Item={
            "username": request.form["username"],
            "email": request.form["email"],
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.utcnow().isoformat()
        })

        sns.subscribe(
            TopicArn=TOPIC_ARN,
            Protocol="email",
            Endpoint=request.form["email"]
        )

        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        res = users_table.get_item(Key={"username": request.form["username"]})
        user = res.get("Item")

        if user and check_password_hash(user["password"], request.form["password"]):
            session["user"] = user["username"]
            return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/favorites")
def favorites():
    if "user" not in session:
        return redirect(url_for("login"))

    res = favorites_table.query(
        KeyConditionExpression=Key("username").eq(session["user"])
    )

    coins = [i["coin"] for i in res.get("Items", [])]
    prices = fetch_prices_for_coins(coins)

    return render_template("favorites.html", prices=prices, favorite_coins=coins)

@app.route("/add_favorite/<coin_id>")
def add_favorite(coin_id):
    favorites_table.put_item(Item={
        "username": session["user"],
        "coin": coin_id
    })
    return redirect(url_for("favorites"))

@app.route("/remove_favorite/<coin_id>")
def remove_favorite(coin_id):
    favorites_table.delete_item(
        Key={"username": session["user"], "coin": coin_id}
    )
    return redirect(url_for("favorites"))

@app.route("/set_alert", methods=["POST"])
def set_alert():
    res = users_table.get_item(Key={"username": session["user"]})
    email = res["Item"]["email"]

    coin = request.form.get("coin")
    threshold = request.form.get("threshold")

    alerts_table.put_item(Item={
        "alert_id": f"{email}#{coin}",
        "email": email,
        "coin": coin,
        "threshold": str(threshold),
        "cooldown": "0"
    })

    return redirect(url_for("favorites"))

# ================= RUN =================

if __name__ == "__main__":
    threading.Thread(target=check_alerts_background, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
