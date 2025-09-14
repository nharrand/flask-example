from flask import Flask, request, jsonify
from api_logic import normalize_tags

app = Flask(__name__)

@app.post("/normalize")
def normalize():
    payload = request.get_json(force=True, silent=True) or {}
    tags = payload.get("tags")
    result = normalize_tags(tags)
    return jsonify({"tags": result})

if __name__ == "__main__":
    app.run(debug=True)
