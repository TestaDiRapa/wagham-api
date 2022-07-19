import configparser
import datetime
import os
import requests
from flask import Flask, jsonify, make_response, send_file, request
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt

CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static/secret/config.ini"))
EXPIRATION = datetime.timedelta(hours=1)

ROLE_MAP = {
    "699175663009267732": "I Cavalieri di Malto",
    "704974771376488459": "Master 3",
    "704974466525954178": "Master 2",
    "699240480373997589": "Master 1",
    "757896706472935465": "Delegato di Gilda",
    "699241511098908814": "Gildano",
    "880481772066971658": "Aspirante Gildano"
}

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = CONFIG["JWT"]["secret"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = EXPIRATION
jwt = JWTManager(app)

client_id = CONFIG["DISCORD"]["client_id"]
client_secret = CONFIG["DISCORD"]["client_secret"]

def discord_me_request(discord_token: str) -> requests.Response:
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {discord_token}'
    }
    return requests.get('https://discord.com/api/users/@me', headers=headers)

def refresh_discord_token(token): 
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': token
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    return requests.post("https://discord.com/api/v10/oauth2/token", data=payload, headers=headers)

def get_wagham_role(discord_token: str, discord_id: str) -> str: 
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {discord_token}'
    }
    guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers=headers)
    if guilds_response.status_code != 200:
        return "NOT_IN_SERVER"
    is_wagham = len(filter(lambda x: x["id"] == CONFIG["DISCORD"]["wagham_id"], guilds_response.json())) > 0
    if not is_wagham:
        return "NOT_IN_SERVER"
    member_info_response = requests.get(f'https://discord.com/api/users/@me/guilds/{CONFIG["DISCORD"]["wagham_id"]}/member', headers=headers)
    if member_info_response.status_code != 200:
        return "NOT_IN_SERVER"
    for k, v in ROLE_MAP:
        if k in member_info_response.json["roles"]:
            return v

@app.route('/user', methods=['GET'])
def user():
    if request.method == 'GET':
        code = request.args.get('code', default=None, type=str)
        if code is None:
            return make_response("Bad request", 400)
        payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://localhost:8100/tabs/character',
            'scope': 'identify',
            'code': code
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        discord_token_response = requests.post('https://discord.com/api/v10/oauth2/token', data=payload, headers=headers)
        if discord_token_response.status_code != 200:
            return make_response('Cannot obtain Discord OAuth token', discord_token_response.status_code)
        discord_token = discord_token_response.json()['access_token']
        discord_token_expiration = discord_token_response.json()['expires_in']
        discord_refresh_token = discord_token_response.json()['refresh_token']
        me_response = discord_me_request(discord_token)
        if me_response.status_code != 200:
            return make_response('Cannot get identity', me_response.status_code)
        identity = me_response.json()['id']
        role = get_wagham_role(discord_token, identity)
        access_token = create_access_token(identity=identity)
        refresh_token = create_refresh_token(identity=identity)
        return jsonify(access_token=access_token, expires_in=EXPIRATION.seconds, refresh_token=refresh_token,
                        discord_token=discord_token, discord_expiration=discord_token_expiration,
                        discord_refresh_token=discord_refresh_token, role=role)

@app.route('/content/images/<image_filename>', methods=['GET'])
def content_image(image_filename: str):
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static/content/img", image_filename))

if __name__ == "__main__":
    app.run()