import pyrebase
import json
import fastapi
import uvicorn
import httpx
import redis

from requests import HTTPError
from fastapi import Depends
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from service_provider import *
from service_connector import ServiceConnector

app = fastapi.FastAPI()
httpxClient = httpx.AsyncClient()
store = redis.Redis()
pb = pyrebase.initialize_app(json.load(open('firebase_config.json')))
auth = pb.auth()


# Todo: Create an "EnableServiceProvider" endpoint that first verifies login creds and get user's id.
# Todo: It also gets as input API_KEY, API_SECRET, CLIENT_ID, CLIENT_SECRET, SCOPES.
# Todo: It will be documented to use a generic redirect_url "authorization-success" for that service provider.
# Todo: It will store these information as a field-value pair with key being user's id.
# Todo: It will return success.

# Todo: Create an "AuthorizeServiceProvider" endpoint that first verifies login creds and get user's id.
# Todo: It also gets as input the end_user_id in the above request.
# Todo: Then this function generates a state and store it as a field in a field-value pair with key being "STATE".
# Todo: The value for above state field would be concatenation of user_id and end_user_id.

# Todo: Create an "authorization-success" endpoint. When the user approves the request, Service provider will hit this.
# Todo: It will get the state and code information from the Service Provider.
# Todo: It will generate the access and refresh tokens for that particular end-user.
# Todo: It will save above details in a field:value pair with user_id_end_user_id key.

# Todo: Create a "get_access_token" for each service provider. It first verifies login creds and get user's id.
# Todo: It also gets as input end_user_id key.
# Todo: It will use this info to get access_token and return it to the user.


@app.post("/signup")
async def signup(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = auth.create_user_with_email_and_password(
            email=form_data.username,
            password=form_data.password
        )
        email_verification = auth.send_email_verification(id_token=user.get("idToken"))
        return JSONResponse(
            content={'message': f'Successfully created user. Please verify your email {user.get("email")}'},
            status_code=200)
    except HTTPError as e:
        error_dict = json.loads(e.strerror)["error"]
        return HTTPException(detail={'message': error_dict.get("message")}, status_code=error_dict.get("code"))


@app.get('/home')
def home():
    html_content = """<form action="authorize-atlassian"> <button type="submit">Authorize Atlassian</button> </form> 
    <form action="authorize-google"> <button type="submit">Authorize Google</button> </form> <form 
    action="authorize-slack"> <button type="submit">Authorize Slack</button> </form>"""
    return HTMLResponse(content=html_content, status_code=200)


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
async def enable_provider(provider: str, api_key: str, api_secret: str, client_id: str, client_secret: str, scopes: str,
                          user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=provider, api_key=api_key, api_secret=api_secret,
                                 client_id=client_id, client_secret=client_secret, scopes=scopes)
    await connector.save_provider()


@app.post('/authorize-twitter')
async def authorize_twitter(end_user_id: str, user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Twitter.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'code_challenge': 'challenge',
                       'code_challenge_method': 'plain'},
        user_id=user_id,
        end_user_id=end_user_id)
    return authorization_url


@app.post('/authorize-atlassian')
async def authorize_atlassian(end_user_id: str, user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Atlassian.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'audience': 'api.atlassian.com'},
        user_id=user_id,
        end_user_id=end_user_id)
    return RedirectResponse(authorization_url)


@app.post('/authorize-google')
async def authorize_google(end_user_id: str, user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Google.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'access_type': 'offline'},
        user_id=user_id,
        end_user_id=end_user_id)
    return RedirectResponse(authorization_url)


@app.post('/authorize-slack')
async def authorize_slack(end_user_id: str, user_id: str = Depends(validate_login_creds)):
    connector = ServiceConnector(user_id=user_id, provider=Slack.name)
    authorization_url = await connector.get_authorization_url(
        extras_params={'user_scope': connector.scopes},
        user_id=user_id,
        end_user_id=end_user_id)
    return RedirectResponse(authorization_url)


@app.get(f'/{Twitter.redirect_uri}')
async def twitter_authorization_success(code: str, state: str):
    if store.hexists("STATE", state):
        key = store.hget("STATE", state)
        user_id = key[0:key.find("::")]
        store.hdel("STATE", state)
    else:
        raise ValueError("Incorrect STATE received.")
    connector = ServiceConnector(user_id=user_id, provider=Twitter.name)
    oauth_token = await connector.fetch_user_oauth_token(code=code, code_verifier='challenge')
    connector.persist_oauth_token(oauth2_token=oauth_token, key=key)
    return RedirectResponse('/home')


@app.get(f'/{Google.redirect_uri}')
async def google_authorization_success(code: str, state: str):
    if store.hexists("STATE", state):
        key = store.hget("STATE", state)
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
        key = store.hget("STATE", state)
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
        key = store.hget("STATE", state)
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


@app.get('/get-access-token')
async def get_access_token(end_user_id: str, provider: str, user_id: str = Depends(validate_login_creds)):
    key = f"{user_id}::{end_user_id}"
    connector = ServiceConnector(user_id=user_id, provider=provider)
    return await connector.get_access_token(key=key)

if __name__ == '__main__':
    uvicorn.run(app='main:app', port=8000)
