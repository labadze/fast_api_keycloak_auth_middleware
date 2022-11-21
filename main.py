import os

import httpx
import requests
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, HTTPException
from starlette import status
from starlette.requests import Request
from starlette.responses import RedirectResponse

app = FastAPI()

oauth = OAuth()
issuer = os.getenv('ISSUER', 'http://localhost:8080/auth/realms/fast-api-oauth-lib')
client_id = os.getenv('CLIENT_ID', 'fast-api-oauth-lib')
client_secret = os.getenv('CLIENT_SECRET', 'UB8uxVJFRoa30HFukKA1PePXhcBM8Dpt')
oidc_discovery_url = f'{issuer}/.well-known/openid-configuration'
callback_url = 'http://localhost:8010/auth'
end_session_endpoint = f'{issuer}/protocol/openid-connect/logout'

oauth.register(
    name='keycloak',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url=oidc_discovery_url,
    client_kwargs={
        'scope': 'openid email profile',
        'code_challenge_method': 'S256'  # enable PKCE
    },
)


@app.get("/")
async def root(request: Request):
    return await oauth.keycloak.authorize_redirect(request, callback_url)


@app.get("/auth")
async def keycloak_callback(request: Request):
    token = await oauth.keycloak.authorize_access_token(request)
    # user = token['userinfo']
    client = httpx.AsyncClient(http2=True)
    headers = {
        "x_http_h_a": token["access_token"],
        "x_http_h_r": token["refresh_token"],
        "content-type": "application/json"
    }
    result = await client.get(url="http://localhost:8007", headers=headers)
    if result.status_code == 201:
        return RedirectResponse('http://localhost:8007/', status_code=status.HTTP_303_SEE_OTHER)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized...",
            headers={"WWW-Authenticate": "HttpCookie"},
        )


@app.get("/current_user")
async def fetch_current_user(request: Request):
    x_http_h_a = request.headers.get("x_http_h_a")
    client = httpx.AsyncClient(http2=True)
    headers = {
        "Authorization": "Bearer {access_token}".format(access_token=x_http_h_a),
        "content-type": "application/json"
    }
    result = await client.get(url="http://localhost:8080/auth/realms/demo/protocol/openid-connect/userinfo",
                              headers=headers)
    return result.json()


@app.get("/log_out")
async def fetch_current_user(request: Request):
    x_http_h_r = request.headers.get("x_http_h_r")
    data = {"client_id": client_id, "client_secret": client_secret, "refresh_token": str(x_http_h_r)}
    headers = {
        "content-type": "application/x-www-form-urlencoded"
    }
    result = requests.post(url=end_session_endpoint, data=data, headers=headers)
    if result.status_code == 204:
        return RedirectResponse('http://localhost:8007/delete_cookies', status_code=status.HTTP_303_SEE_OTHER)
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Not successful...",
            headers={"Keycloak-Error": "Logout State"},
        )
