from flask import Flask, jsonify, request, session, url_for, redirect, abort
from flask_restful import Api, Resource
from flask_cors import cross_origin, CORS
from authlib.integrations.flask_client import OAuth, OAuthError
from functools import wraps
from urllib.parse import quote_plus, urlencode

from authlib.jose import JsonWebToken, JWTClaims, JsonWebEncryption
import json
import base64
import os
from dotenv import load_dotenv
import requests

import secrets

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = secrets.token_urlsafe(16)
app.config['AUTH0_DOMAIN'] = os.getenv('AUTH0_DOMAIN')
app.config['AUTH0_CLIENT_ID'] = os.getenv('AUTH0_CLIENT_ID')
app.config['AUTH0_CLIENT_SECRET'] = os.getenv('AUTH0_CLIENT_SECRET')
app.config['AUTH0_API_AUDIENCE'] = os.getenv('AUTH0_API_AUDIENCE')

app.config['SESSION_TYPE'] = 'filesystem'

api = Api(app)
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=app.config['AUTH0_CLIENT_ID'],
    client_secret=app.config['AUTH0_CLIENT_SECRET'],
    # api_base_url=f'https://{app.config["AUTH0_DOMAIN"]}',
    # access_token_url=f'https://{app.config["AUTH0_DOMAIN"]}/oauth/token',
    # authorize_url=f'https://{app.config["AUTH0_DOMAIN"]}/authorize',
    server_metadata_url=f'https://{app.config["AUTH0_DOMAIN"]}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

