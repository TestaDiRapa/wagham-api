import os
import requests
from constants import CONFIG, EXPIRATION, TIER_REWARDS, ROLE_MAP
from flask import Flask, jsonify, make_response, send_file, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from waghamdb import WaghamDB

db = WaghamDB(CONFIG, TIER_REWARDS)

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = CONFIG["JWT"]["secret"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = EXPIRATION
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = False
jwt = JWTManager(app)

client_id = CONFIG["DISCORD"]["client_id"]
client_secret = CONFIG["DISCORD"]["client_secret"]

def discord_me_request(discord_token: str) -> requests.Response:
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {discord_token}'
    }
    return requests.get('https://discord.com/api/users/@me', headers=headers)

def get_wagham_role(discord_token: str) -> str: 
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {discord_token}'
    }
    guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers=headers)
    if guilds_response.status_code != 200:
        return "NOT_IN_SERVER"
    is_wagham = len(list(filter(lambda x: x["id"] == CONFIG["DISCORD"]["wagham_id"], guilds_response.json()))) > 0
    if not is_wagham:
        return "NOT_IN_SERVER"
    member_info_response = requests.get(f'https://discord.com/api/users/@me/guilds/{CONFIG["DISCORD"]["wagham_id"]}/member', headers=headers)
    if member_info_response.status_code != 200:
        return "NOT_IN_SERVER"
    for k, v in ROLE_MAP.items():
        if k in member_info_response.json()["roles"]:
            return v

@app.route('/discord', methods=['POST'])
def refresh_discord_token(): 
    if request.method == 'POST':
        post_body = request.get_json()
        if 'token' not in post_body:
            return make_response('Missing refresh token', 400)
        payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': post_body['token']
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        token_response = requests.post('https://discord.com/api/oauth2/token', data=payload, headers=headers)
        if token_response.status_code != 200:
            return make_response("", token_response.status_code)
        discord_token = token_response.json()['access_token']
        discord_token_expiration = token_response.json()['expires_in']
        discord_refresh_token = token_response.json()['refresh_token']
        return jsonify(discord_token=discord_token, discord_expiration=discord_token_expiration,
                        discord_refresh_token=discord_refresh_token)
    else:
        return make_response("", 405)

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    if request.method == 'POST':
        post_body = request.get_json()
        # if 'discordToken' not in post_body:
        #    return make_response('Missing discord token', 400)
        # role = get_wagham_role(post_body['discordToken'])
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token, expires_in=EXPIRATION.seconds)
    else:
        return make_response("", 405)

@app.route('/auth', methods=['GET'])
def auth():
    if request.method == 'GET':
        code = request.args.get('code', default=None, type=str)
        if code is None:
            return make_response("Bad request", 400)
        payload = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://localhost:8100/tabs/home',
            'scope': 'identify',
            'code': code
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        discord_token_response = requests.post('https://discord.com/api/oauth2/token', data=payload, headers=headers)
        if discord_token_response.status_code != 200:
            return make_response('Cannot obtain Discord OAuth token', discord_token_response.status_code)
        discord_token = discord_token_response.json()['access_token']
        discord_token_expiration = discord_token_response.json()['expires_in']
        discord_refresh_token = discord_token_response.json()['refresh_token']
        me_response = discord_me_request(discord_token)
        if me_response.status_code != 200:
            return make_response('Cannot get identity', me_response.status_code)
        identity = me_response.json()['id']
        role = get_wagham_role(discord_token)
        access_token = create_access_token(identity=identity)
        refresh_token = create_refresh_token(identity=identity)
        return jsonify(access_token=access_token, expires_in=EXPIRATION.seconds, refresh_token=refresh_token,
                        discord_token=discord_token, discord_expiration=discord_token_expiration,
                        discord_refresh_token=discord_refresh_token, role=role)
    else:
        return make_response("", 405)

@app.route('/content/images/<image_filename>', methods=['GET'])
def content_image(image_filename: str):
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static/content/img", image_filename))

@app.route('/character', methods=['GET'])
@jwt_required()
def character_handler():
    if request.method == 'GET':
        identity = get_jwt_identity()
        character = db.get_active_character(identity)
        if character is None:
            return make_response("", 404)
        else:
            return jsonify(character)
    else:
        return make_response("", 405)

if __name__ == "__main__":
    app.run()