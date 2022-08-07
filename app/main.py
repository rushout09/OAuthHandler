import pyrebase
import json
import fastapi
import httpx
import redis

from requests import HTTPError
from fastapi import Depends
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.param_functions import Form
from app.service_provider import *
from app.service_connector import ServiceConnector

app = fastapi.FastAPI()
httpxClient = httpx.AsyncClient()
store = redis.Redis()
pb = pyrebase.initialize_app(json.load(open('firebase_config.json')))
auth = pb.auth()


@app.post("/signup")
async def signup(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = auth.create_user_with_email_and_password(
            email=form_data.username,
            password=form_data.password
        )
        # Todo: verify if email sent.
        email_verification = auth.send_email_verification(id_token=user.get("idToken"))
        return JSONResponse(
            content={'message': f'Successfully created user. Please verify your email {user.get("email")}'},
            status_code=200)
    except HTTPError as e:
        error_dict = json.loads(e.strerror)["error"]
        return HTTPException(detail={'message': error_dict.get("message")}, status_code=error_dict.get("code"))


def validate_login_creds(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = auth.sign_in_with_email_and_password(form_data.username, form_data.password)
        account_info = auth.get_account_info(id_token=user.get("idToken"))
        user_email_verified = account_info.get("users")[0].get("emailVerified")
        if not user_email_verified:
            str_error = {
                "error": {
                    "message": "Email not verified. Please verify email.",
                    "code": 400
                }
            }
            error = HTTPError
            error.strerror = json.dumps(str_error)
            raise error
        user_id: str = account_info.get("users")[0].get("localId")
        return user_id
    except HTTPError as e:
        error_dict = json.loads(e.strerror)["error"]
        return HTTPException(detail={'message': error_dict.get("message")}, status_code=error_dict.get("code"))


@app.post('/enable-provider')
async def enable_provider(provider: str = Form(), api_key: str = Form(), api_secret: str = Form(),
                          user_redirect_url: str = Form(), client_id: str = Form(), client_secret: str = Form(),
                          scopes: str = Form(), user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=provider, api_key=api_key, api_secret=api_secret,
                                 user_redirect_url=user_redirect_url,
                                 client_id=client_id, client_secret=client_secret, scopes=scopes)
    await connector.save_provider()
    # Todo: Return correct response.


@app.post('/authorize-twitter')
async def authorize_twitter(end_user: str = Form(), user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Twitter.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'code_challenge': 'challenge',
                       'code_challenge_method': 'plain'},
        user_id=user_id,
        end_user_id=end_user)
    return authorization_url


@app.post('/authorize-atlassian')
async def authorize_atlassian(end_user: str = Form(), user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Atlassian.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'audience': 'api.atlassian.com'},
        user_id=user_id,
        end_user_id=end_user)
    return authorization_url


@app.post('/authorize-google')
async def authorize_google(end_user: str = Form(), user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Google.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'access_type': 'offline'},
        user_id=user_id,
        end_user_id=end_user)
    return authorization_url


@app.post('/authorize-slack')
async def authorize_slack(end_user: str = Form(), user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Slack.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'user_scope': connector.scopes},
        user_id=user_id,
        end_user_id=end_user)
    return authorization_url


@app.get(f'/{Twitter.redirect_uri}')
async def twitter_authorization_success(code: str, state: str):
    if store.hexists("STATE", state):
        key = store.hget("STATE", state).decode("utf-8")
        user_id = key[0:key.find("::")]
        store.hdel("STATE", state)
    else:
        raise ValueError("Incorrect STATE received.")
    connector = ServiceConnector(user_id=user_id, provider=Twitter.name)
    oauth_token = await connector.fetch_user_oauth_token(code=code, code_verifier='challenge')
    connector.persist_oauth_token(oauth2_token=oauth_token, key=key)
    redirect_url = store.hget(user_id, f"{Twitter.name}_REDIRECT_URL").decode("utf-8")
    return RedirectResponse(redirect_url)


@app.get(f'/{Google.redirect_uri}')
async def google_authorization_success(code: str, state: str):
    if store.hexists("STATE", state):
        key = store.hget("STATE", state).decode("utf-8")
        user_id = key[0:key.find("::")]
        store.hdel("STATE", state)
    else:
        raise ValueError("Incorrect STATE received.")
    connector = ServiceConnector(user_id=user_id, provider=Google.name)
    oauth_token = await connector.fetch_user_oauth_token(code=code, code_verifier=None)
    connector.persist_oauth_token(oauth2_token=oauth_token, key=key)
    return RedirectResponse('/home')


@app.get(f'/{Slack.redirect_uri}')
async def slack_authorization_success(code: str, state: str):
    if store.hexists("STATE", state):
        key = store.hget("STATE", state).decode("utf-8")
        user_id = key[0:key.find("::")]
        store.hdel("STATE", state)
    else:
        raise ValueError("Incorrect STATE received.")
    connector = ServiceConnector(user_id=user_id, provider=Slack.name)
    oauth_token = await connector.fetch_user_oauth_token(code=code, code_verifier=None)
    connector.persist_oauth_token(oauth2_token=oauth_token, key=key)
    return RedirectResponse('/home')


@app.get(f'/{Atlassian.redirect_uri}')
async def atlassian_authorization_success(code: str, state: str):
    if store.hexists("STATE", state):
        key = store.hget("STATE", state).decode("utf-8")
        user_id = key[0:key.find("::")]
        store.hdel("STATE", state)
    else:
        raise ValueError("Incorrect STATE received.")
    connector = ServiceConnector(user_id=user_id, provider=Atlassian.name)
    oauth_token = await connector.fetch_user_oauth_token(code=code, code_verifier=None)
    connector.persist_oauth_token(oauth2_token=oauth_token, key=key)
    atlassian_access_token = connector.get_access_token(key=key)

    response: httpx.Response = await httpxClient.get(url='https://api.atlassian.com/oauth/token/accessible-resources',
                                                     headers={'Authorization': f"Bearer {atlassian_access_token}",
                                                              'Accept': 'application/json'})
    atlassian_cloud_id = response.json()[0]['id']
    atlassian_cloud_url = response.json()[0]['url']

    store.hset(key, f"{connector.provider.name}_CLOUD_ID", str(atlassian_cloud_id))
    store.hset(key, f"{connector.provider.NAME}_CLOUD_URL", str(atlassian_cloud_url))

    return RedirectResponse('/home')


@app.post('/get-access-token')
async def get_access_token(end_user: str = Form(), provider: str = Form(),
                           user_id: str = Depends(validate_login_creds)):
    key = f"{user_id}::{end_user}"
    connector = ServiceConnector(user_id=user_id, provider=provider)
    return await connector.get_access_token(key=key)
