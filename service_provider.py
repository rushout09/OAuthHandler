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

load_dotenv()
store = redis.Redis()

# HOST_URL: str = 'https://rushabh.loca.lt'
HOST_URL = os.getenv('HOST_URL')

KEY = os.getenv('KEY')
cipher = Fernet(KEY.encode("utf-8"))

timeout = httpx.Timeout(10.0)

# Todo: A state must be generated for that particular user while he tries to authenticate to that particular service.
# Todo: when the service provider calls "authorization_success" api along with state, use the state to fetch the user.
# Todo: Store the oauth token fetched from the code to redis.

# Todo: Add Twitter as source.

# Todo: Research way to invalidate token and show token status. p1
# Todo: Store the jwt token on redis. invalidate and generate new token (requires username and password).

# Todo: Add user session management using cookies.

# Todo: Possible sources to add: Twitter, MS Outlook, Teams, onedrive, intercom, CRMs, Github search. p2
# Todo: Add unit tests. p1


class BaseServiceProvider:
    API_SECRET: str
    API_KEY: str
    NAME: str
    CLIENT_ID: str
    CLIENT_SECRET: str
    REDIRECT_URI: str
    REDIRECT_URL: str
    SCOPES: str
    AUTH_URL: str
    TOKEN_URL: str
    REFRESH_URL: str
    oauth: OAuth2

    @classmethod
    async def fetch_user_oauth_token(cls, code: Optional[str], state: Optional[str], code_verifier: Optional[str]):
        if store.hexists("STATE", state):
            user_id = store.hget("STATE", state)
            store.hdel("STATE", state)
            if cls.NAME == TwitterServiceProvider.NAME:
                auth = cls.API_KEY + ":" + cls.API_SECRET
                b64_bearer_token_creds = base64.b64encode(auth.encode('utf8'))
                cls.oauth.request_headers['User-Agent'] = "TheBotCreator"
                cls.oauth.request_headers['Authorization'] = 'Basic ' + b64_bearer_token_creds.decode('utf8')
                cls.oauth.request_headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8'

            oauth_token = await cls.oauth.get_access_token(code=code, redirect_uri=cls.REDIRECT_URL,
                                                           code_verifier=code_verifier)
            if cls.NAME == SlackServiceProvider.NAME:
                oauth_token = SlackServiceProvider.fix_access_token(oauth_token)
            return user_id, oauth_token

    @classmethod
    async def get_access_token(cls, user_id):
        if store.hget(user_id, f"{cls.NAME}_ACCESS"):
            access_token = cipher.decrypt((store.hget(user_id, f"{cls.NAME}_ACCESS"))).decode("utf-8")
            expiry_time = int(store.hget(user_id, f"{cls.NAME}_EXPIRES_AT").decode("utf-8"))
            if expiry_time < int(round(datetime.now(tz=timezone.utc).timestamp())):
                oauth2_token = await cls.refresh_oauth_token()
                cls.persist_oauth_token(oauth2_token=oauth2_token, user_id=user_id)
                access_token = cipher.decrypt((store.hget(user_id, f"{cls.NAME}_ACCESS"))).decode("utf-8")
            return access_token
        return None

    @classmethod
    def persist_oauth_token(cls, oauth2_token: dict, user_id: str):
        access_token = oauth2_token.get('access_token')
        refresh_token = oauth2_token.get('refresh_token')
        expires_at = oauth2_token.get('expires_in') + int(round(datetime.now(tz=timezone.utc).timestamp()))
        scopes = oauth2_token.get('scope')

        store.hset(user_id, f"{cls.NAME}_ACCESS", cipher.encrypt(access_token.encode("utf-8")))
        if refresh_token is not None:
            store.hset(user_id, f"{cls.NAME}_REFRESH", cipher.encrypt(refresh_token.encode("utf-8")))
        store.hset(user_id, f"{cls.NAME}_EXPIRES_AT", str(expires_at))
        store.hset(user_id, f"{cls.NAME}_SCOPES", scopes)

    @classmethod
    async def refresh_oauth_token(cls):
        print(cls)
        print(cls.NAME)
        refresh_token = cipher.decrypt((store.hget(cls.NAME, 'REFRESH'))).decode("utf-8")
        print("refreshing access token")
        return await cls.oauth.refresh_token(refresh_token=refresh_token)

    @classmethod
    async def get_authorization_url(cls, extras_params: dict, user_id: str):
        state = cls.generate_token()
        store.hset("STATE", state, user_id)
        return await cls.oauth.get_authorization_url(
            redirect_uri=cls.REDIRECT_URL,
            state=state,
            extras_params=extras_params)

    @classmethod
    def generate_token(cls, length=30, chars=UNICODE_ASCII_CHARACTER_SET):
        """Generates a non-guessable OAuth token

        OAuth (1 and 2) does not specify the format of tokens except that they
        should be strings of random characters. Tokens should not be guessable
        and entropy when generating the random characters is important. Which is
        why SystemRandom is used instead of the default random.Choice method.
        """
        rand = SystemRandom()
        return ''.join(rand.choice(chars) for _ in range(length))


class GoogleServiceProvider(BaseServiceProvider):
    NAME: str = 'google'
    CLIENT_ID: str = os.getenv('GOOGLE_CLIENT_ID')
    CLIENT_SECRET: str = os.getenv('GOOGLE_CLIENT_SECRET')
    REDIRECT_URI: str = 'gdrive-authorization-success'
    REDIRECT_URL: str = f'{HOST_URL}/{REDIRECT_URI}'
    SCOPES: list = ['https://www.googleapis.com/auth/drive.readonly', 'https://www.googleapis.com/auth/gmail.readonly']
    AUTH_URL: str = 'https://accounts.google.com/o/oauth2/v2/auth'
    TOKEN_URL: str = 'https://www.googleapis.com/oauth2/v4/token'
    REFRESH_URL: str = 'https://www.googleapis.com/oauth2/v4/token'
    GDRIVE_API_URL: str = 'https://www.googleapis.com/drive/v3/files'
    GMAIL_API_URL: str = 'https://gmail.googleapis.com/gmail/v1/users/me/messages'

    oauth: OAuth2 = OAuth2(
        name=NAME,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        authorize_endpoint=AUTH_URL,
        access_token_endpoint=TOKEN_URL,
        refresh_token_endpoint=REFRESH_URL,
        base_scopes=SCOPES)


class TwitterServiceProvider(BaseServiceProvider):
    NAME: str = 'twitter'
    CLIENT_ID: str = os.getenv('TWITTER_CLIENT_ID')
    CLIENT_SECRET: str = os.getenv('TWITTER_CLIENT_SECRET')
    REDIRECT_URI: str = 'twitter-authorization-success'
    REDIRECT_URL: str = f'{HOST_URL}/{REDIRECT_URI}'
    SCOPES: list = ['offline.access', 'tweet.read', 'tweet.write']
    AUTH_URL: str = 'https://twitter.com/i/oauth2/authorize'
    TOKEN_URL: str = 'https://api.twitter.com/2/oauth2/token'
    REFRESH_URL: str = 'https://api.twitter.com/2/oauth2/token'
    API_KEY: str = os.getenv("TWITTER_API_KEY")
    API_SECRET: str = os.getenv("TWITTER_API_SECRET")

    oauth: OAuth2 = OAuth2(
        name=NAME,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        authorize_endpoint=AUTH_URL,
        access_token_endpoint=TOKEN_URL,
        refresh_token_endpoint=REFRESH_URL,
        base_scopes=SCOPES)


class AtlassianServiceProvider(BaseServiceProvider):
    NAME: str = 'atlassian'
    CLIENT_ID: str = os.getenv('ATLASSIAN_CLIENT_ID')
    CLIENT_SECRET: str = os.getenv('ATLASSIAN_CLIENT_SECRET')
    REDIRECT_URI = 'atlassian-authorization-success'
    REDIRECT_URL: str = f'{HOST_URL}/{REDIRECT_URI}'
    SCOPES: list = ['read:content-details:confluence',
                    'read:issue-details:jira', 'read:audit-log:jira', 'read:avatar:jira',
                    'read:field-configuration:jira', 'read:issue-meta:jira', 'offline_access']
    AUTH_URL: str = 'https://auth.atlassian.com/authorize'
    TOKEN_URL: str = 'https://auth.atlassian.com/oauth/token'
    REFRESH_URL: str = 'https://auth.atlassian.com/oauth/token'
    CONFLUENCE_API_URL: str = 'https://api.atlassian.com/ex/confluence'
    JIRA_API_URL: str = 'https://api.atlassian.com/ex/jira'

    oauth: OAuth2 = OAuth2(
        name=NAME,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        authorize_endpoint=AUTH_URL,
        access_token_endpoint=TOKEN_URL,
        refresh_token_endpoint=REFRESH_URL,
        base_scopes=SCOPES)


class SlackServiceProvider(BaseServiceProvider):
    NAME: str = 'slack'
    CLIENT_ID: str = os.getenv('SLACK_CLIENT_ID')
    CLIENT_SECRET: str = os.getenv('SLACK_CLIENT_SECRET')
    REDIRECT_URI = 'slack-authorization-success'
    REDIRECT_URL: str = f'{HOST_URL}/{REDIRECT_URI}'
    SCOPES: str = None
    USER_SCOPES: str = 'search:read'
    AUTH_URL: str = 'https://slack.com/oauth/v2/authorize'
    TOKEN_URL: str = 'https://slack.com/api/oauth.v2.access'
    REFRESH_URL: str = 'https://slack.com/api/oauth.v2.access'
    SLACK_API_URL: str = 'https://slack.com/api/search.all'
    oauth: OAuth2 = OAuth2(
        name=NAME,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        authorize_endpoint=AUTH_URL,
        access_token_endpoint=TOKEN_URL,
        refresh_token_endpoint=REFRESH_URL,
        base_scopes=SCOPES)

    @staticmethod
    def fix_access_token(params: dict) -> dict:
        access_token = params.get('authed_user')
        access_token['token_type'] = 'Bearer'
        return access_token
