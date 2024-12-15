"""
This illustrates how to do the password OAuth2 flow with FastAPI.

Source:

https://fastapi.tiangolo.com/tutorial/security/
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import uvicorn

# Proxy for a database.
# Note it stores only the hash for a password.
# And that it can store arbitrary metadata for a user also - such as <disabled>.
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()


def fake_hash_password(password: str):
    """
    A pathetic but illustrative password hashing function.
    """
    return "fakehashed" + password


# An access control <Dependency> for a route that demands that an OAuth2 bearer token is
# presented in the request's header.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    """
    Pydantic model for a User - excluding any auth-ness, but including arbitrary meta data like <disabled>.
    """

    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    """
    Mixes-in a hashed password to a User.
    """

    hashed_password: str


def get_user(db, username: str):
    """
    Fake DB lookup for a UserInDB for the given username.
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    Offers to decode a User object from a given token.
    """
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,  # Very specific error code.
            detail="Invalid authentication credentials",
            headers={
                "WWW-Authenticate": "Bearer"
            },  # Error response headers required by OAuth2.
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Illustrative user getter that takes an interest in the user's metadata.
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """
    The token exchange path operation, that replies with an OAuth2 token response IFF the request carries
    a valid OAuth2 username and password FORM payload AND the hash of the password presented matches the
    stored password hash for that user.

    Note that the OAuth2PasswordRequestForm class has no special significance to FastAPI nor to OpenAPI.
    It's just a plain class to bind expected FORM data.
    """

    # We read <username> from the OAuth2 mandatory form, but it also carries
    # scopes, client_id and client_secret and optional <grant_type>.
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        # Bad Request - cannot or will not for both no such user, AND for wrong password.
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    """
    Illustrates the authentication guard on a route.
    """
    return current_user


if __name__ == "__main__":
    uvicorn.run("main:app", port=5000, log_level="info")
