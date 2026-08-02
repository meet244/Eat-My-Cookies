from flask import Flask, request, jsonify
import os

from pymongo import MongoClient
from dotenv import load_dotenv

# Load the .env file that sits next to this script, regardless of the
# directory the server is started from.
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)

# --- MongoDB Atlas configuration (values come from environment variables) ---
MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "extension_db")
MONGODB_COLLECTION = os.getenv("MONGODB_COLLECTION", "users")

collection = None
if MONGODB_URI:
    client = MongoClient(MONGODB_URI)
    collection = client[MONGODB_DB][MONGODB_COLLECTION]
    # username is unique per user, so enforce that at the database level.
    collection.create_index("username", unique=True)
else:
    print("WARNING: MONGODB_URI is not set. Set it before sending data.")


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

@app.route("/data", methods=["POST", "OPTIONS"])
def data():
    if request.method == "OPTIONS":
        return ("", 204)

    if collection is None:
        return jsonify({"error": "database not configured"}), 500

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "expected a JSON object"}), 400

    if payload:
        payload['username'] = payload.get('meta', {}).get('name', 'unknown')

    username = payload.get("username")

    # Only proceed when we have a real username.
    if not username or username == "unknown":
        return jsonify({"error": "missing or unknown username; not saved"}), 400

    # Map the data by username: one document per user, overwritten on each send.
    collection.replace_one({"username": username}, payload, upsert=True)

    return jsonify({"status": "ok", "username": username}), 200

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "Welcome to the Data API"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, debug=True)
