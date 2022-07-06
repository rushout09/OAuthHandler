import base64
from typing import Optional

import httpx
import os
import redis
from dotenv import load_dotenv
from datetime import datetime, timezone
from httpx_oauth.oauth2 import OAuth2
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from random import SystemRandom
from cryptography.fernet import Fernet
from service_provider import ServiceProvider, Twitter, Slack

load_dotenv()
store = redis.Redis()

# HOST_URL: str = 'https://rushabh.loca.lt'
HOST_URL = os.getenv('HOST_URL')

KEY = os.getenv('KEY')
cipher = Fernet(KEY.encode("utf-8"))

timeout = httpx.Timeout(10.0)


class ServiceConnector:

    def __init__(self, user_id: str,
                 provider: ServiceProvider,
                 api_secret: str = None,
                 api_key: str = None,
                 client_id: str = None,
                 client_secret: str = None,
                 scopes: str = None):

        self.user_id: str = user_id
        self.provider: ServiceProvider = provider
        self.client_id: Optional[str] = None
        self.client_secret: Optional[str] = None
        self.scopes: Optional[str] = None
        self.api_secret: Optional[str] = None
        self.api_key: Optional[str] = None
        self.redirect_url: str = f"{HOST_URL}/{provider.redirect_uri}"

        if client_id is not None:
            self.client_id = client_id
        else:
            self.client_id = store.hget(user_id, f"{provider.name}_CLIENT_ID")
        if client_secret is not None:
            self.client_secret = client_secret
        else:
            self.client_secret = store.hget(user_id, f"{provider.name}_CLIENT_SECRET")
        if scopes is not None:
            self.scopes = scopes
        else:
            # Todo: check how to store and get scopes as list or string in Redis
            self.scopes = store.hget(user_id, f"{provider.name}_SCOPES")
        if api_secret is not None:
            self.api_secret = api_secret
        elif provider.name == Twitter.name:
            self.api_secret = store.hget(user_id, f"{provider.name}_API_SECRET")
        if api_key is not None:
            self.api_key = api_key
        elif provider.name == Twitter.name:
            self.api_key = store.hget(user_id, f"{provider.name}_API_KEY")

        self.oauth: OAuth2 = OAuth2(
            name=provider.name,
            client_id=self.client_id,
            client_secret=self.client_secret,
            authorize_endpoint=provider.auth_url,
            access_token_endpoint=provider.token_url,
            refresh_token_endpoint=provider.refresh_url,
            base_scopes=self.scopes)

    async def fetch_user_oauth_token(self, code: Optional[str], state: Optional[str], code_verifier: Optional[str]):
        if store.hexists("STATE", state):
            user_id = store.hget("STATE", state)
            store.hdel("STATE", state)
            if self.provider.name == Twitter.name:
                auth = self.api_key + ":" + self.api_secret
                b64_bearer_token_creds = base64.b64encode(auth.encode('utf8'))
                self.oauth.request_headers['User-Agent'] = "TheBotCreator"
                self.oauth.request_headers['Authorization'] = 'Basic ' + b64_bearer_token_creds.decode('utf8')
                self.oauth.request_headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8'

            oauth_token = await self.oauth.get_access_token(code=code, redirect_uri=self.redirect_url,
                                                            code_verifier=code_verifier)
            if self.provider.name == Slack.name:
                oauth_token = self.fix_access_token(oauth_token)
            return user_id, oauth_token

    async def get_access_token(self, user_id):
        if store.hget(user_id, f"{self.provider.name}_ACCESS"):
            access_token = cipher.decrypt((store.hget(user_id, f"{self.provider.name}_ACCESS"))).decode("utf-8")
            expiry_time = int(store.hget(user_id, f"{self.provider.name}_EXPIRES_AT").decode("utf-8"))
            if expiry_time < int(round(datetime.now(tz=timezone.utc).timestamp())):
                oauth2_token = await self.refresh_oauth_token()
                self.persist_oauth_token(oauth2_token=oauth2_token, user_id=user_id)
                access_token = cipher.decrypt((store.hget(user_id, f"{self.provider.name}_ACCESS"))).decode("utf-8")
            return access_token
        return None

    def persist_oauth_token(self, oauth2_token: dict, user_id: str):
        access_token = oauth2_token.get('access_token')
        refresh_token = oauth2_token.get('refresh_token')
        expires_at = oauth2_token.get('expires_in') + int(round(datetime.now(tz=timezone.utc).timestamp()))
        scopes = oauth2_token.get('scope')

        store.hset(user_id, f"{self.provider.name}_ACCESS", cipher.encrypt(access_token.encode("utf-8")))
        if refresh_token is not None:
            store.hset(user_id, f"{self.provider.name}_REFRESH", cipher.encrypt(refresh_token.encode("utf-8")))
        store.hset(user_id, f"{self.provider.name}_EXPIRES_AT", str(expires_at))
        store.hset(user_id, f"{self.provider.name}_SCOPES", scopes)

    async def refresh_oauth_token(self):
        print(self.provider.name)
        refresh_token = cipher.decrypt((store.hget(self.provider.name, 'REFRESH'))).decode("utf-8")
        print("refreshing access token")
        return await self.oauth.refresh_token(refresh_token=refresh_token)

    async def get_authorization_url(self, extras_params: dict, user_id: str):
        state = self.generate_token()
        store.hset("STATE", state, user_id)
        return await self.oauth.get_authorization_url(
            redirect_uri=self.redirect_url,
            state=state,
            extras_params=extras_params)

    @staticmethod
    def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
        """Generates a non-guessable OAuth token

        OAuth (1 and 2) does not specify the format of tokens except that they
        should be strings of random characters. Tokens should not be guessable
        and entropy when generating the random characters is important. Which is
        why SystemRandom is used instead of the default random.Choice method.
        """
        rand = SystemRandom()
        return ''.join(rand.choice(chars) for _ in range(length))

    @staticmethod
    def fix_access_token(params: dict) -> dict:
        access_token = params.get('authed_user')
        access_token['token_type'] = 'Bearer'
        return access_token
