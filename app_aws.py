from flask import Flask, render_template, request, session, redirect, url_for
from datetime import datetime
import requests
import boto3
from werkzeug.security import generate_password_hash, check_password_hash

# ================== CONFIG ==================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

REGION = "us-east-1"
USERS_TABLE = "Users"
SNS_TOPIC_NAME = "user-events"

app = Flask(__name__)
app.secret_key = "super_secret_key_for_crypto_app"

# ================== AWS CLIENTS ==================

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

users_table = dynamodb.Table(USERS_TABLE)

# Fetch SNS topic ARN
topics = sns.list_topics()["Topics"]
TOPIC_ARN = next(
    t["TopicArn"] for t in topics if SNS_TOPIC_NAME in t["TopicArn"]
)

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
            "password": generate_password_hash(request.form["password"]),
            "created_at": datetime.utcnow().isoformat()
        }

        users_table.put_item(Item=user)

        sns.publish(
            TopicArn=TOPIC_ARN,
            Message=f"New user signed up: {user['username']}"
        )

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
    return render_template("favorites.html", prices={})

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
    app.run(host="0.0.0.0", port=5000)
