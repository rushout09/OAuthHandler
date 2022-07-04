import pyrebase
import json
import fastapi
import uvicorn

from requests import HTTPError
from fastapi import Depends
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from service_provider import *

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


@app.post('/authorize-twitter')
async def authorize_twitter(user_id: str = Depends(validate_login_creds)):

    authorization_url = await TwitterServiceProvider.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'code_challenge': 'challenge',
                       'code_challenge_method': 'plain'},
        user_id=user_id)
    return authorization_url


@app.post('/authorize-atlassian')
async def authorize_atlassian(user_id: str = Depends(validate_login_creds)):
    authorization_url = await AtlassianServiceProvider.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'audience': 'api.atlassian.com'},
        user_id=user_id)
    return RedirectResponse(authorization_url)


@app.post('/authorize-google')
async def authorize_google(user_id: str = Depends(validate_login_creds)):
    authorization_url = await GoogleServiceProvider.get_authorization_url(
        extras_params={'prompt': 'consent',
                       'access_type': 'offline'},
        user_id=user_id)
    return RedirectResponse(authorization_url)


@app.post('/authorize-slack')
async def authorize_slack(user_id: str = Depends(validate_login_creds)):
    authorization_url = await SlackServiceProvider.get_authorization_url(
        extras_params={'user_scope': SlackServiceProvider.USER_SCOPES},
        user_id=user_id)
    return RedirectResponse(authorization_url)


@app.get(f'/{TwitterServiceProvider.REDIRECT_URI}')
async def twitter_authorization_success(code: str, state: str):
    user_id, oauth_token = await TwitterServiceProvider.fetch_user_oauth_token(code=code,
                                                                               state=state, code_verifier='challenge')
    TwitterServiceProvider.persist_oauth_token(oauth2_token=oauth_token, user_id=user_id)
    return RedirectResponse('/home')


@app.get(f'/{GoogleServiceProvider.REDIRECT_URI}')
async def google_authorization_success(code: str, state: str):
    user_id, oauth_token = await GoogleServiceProvider.fetch_user_oauth_token(code=code,
                                                                              state=state, code_verifier=None)
    GoogleServiceProvider.persist_oauth_token(oauth2_token=oauth_token, user_id=user_id)
    return RedirectResponse('/home')


@app.get(f'/{SlackServiceProvider.REDIRECT_URI}')
async def slack_authorization_success(code: str, state: str):
    user_id, oauth_token = await SlackServiceProvider.fetch_user_oauth_token(code=code,
                                                                             state=state, code_verifier=None)
    SlackServiceProvider.persist_oauth_token(oauth2_token=oauth_token, user_id=user_id)
    return RedirectResponse('/home')


@app.get(f'/{AtlassianServiceProvider.REDIRECT_URI}')
async def atlassian_authorization_success(code: str, state: str):
    user_id, oauth_token = await AtlassianServiceProvider.fetch_user_oauth_token(code=code,
                                                                                 state=state, code_verifier=None)
    AtlassianServiceProvider.persist_oauth_token(oauth2_token=oauth_token, user_id=user_id)
    atlassian_access_token = AtlassianServiceProvider.get_access_token(user_id=user_id)

    response: httpx.Response = await httpxClient.get(url='https://api.atlassian.com/oauth/token/accessible-resources',
                                                     headers={'Authorization': f"Bearer {atlassian_access_token}",
                                                              'Accept': 'application/json'})
    atlassian_cloud_id = response.json()[0]['id']
    atlassian_cloud_url = response.json()[0]['url']

    store.hset(user_id, f"{AtlassianServiceProvider.NAME}_CLOUD_ID", str(atlassian_cloud_id))
    store.hset(user_id, f"{AtlassianServiceProvider.NAME}_CLOUD_URL", str(atlassian_cloud_url))

    return RedirectResponse('/home')

if __name__ == '__main__':
    uvicorn.run(app='main:app', port=8000)
