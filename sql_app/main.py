import jwt
from fastapi import Depends, FastAPI, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Optional
from . import crud, models, schemas
from .database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Keycloak configuration
KEYCLOAK_BASE_URL = "http://localhost:8080"
REALM_NAME = "tyk"
PUBLIC_KEY_URL = (
    f"{KEYCLOAK_BASE_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs")


def validate_token(access_token: str):
    url = PUBLIC_KEY_URL
    jwks_client = jwt.PyJWKClient(uri=url)

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        data = jwt.decode(access_token, signing_key.key, algorithms=["RS256"],
                          audience="account", options={"verify_exp": True})
        if data["resource_access"].get("crm-service") is None:
            raise HTTPException(status_code=401, detail="Unauthorized Access")
        if "view-crm" not in data["resource_access"]["crm-service"]["roles"]:
            raise HTTPException(status_code=401, detail="Unauthorized Access")
        return data
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid Token")


def get_current_user(authorization: Optional[str] = Header(None)):
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authorization header missing or malformed")
    token = authorization.split(" ")[1]
    return validate_token(token)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/users/{user_id}/items/", response_model=schemas.Item)
def create_item_for_user(
        user_id: int, item: schemas.ItemCreate, db: Session = Depends(get_db)):
    return crud.create_user_item(db=db, item=item, user_id=user_id)


@app.get("/items/", response_model=list[schemas.Item])
def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    items = crud.get_items(db, skip=skip, limit=limit)
    return items


@app.post("/customers/", response_model=schemas.Customer)
def create_customer(
        cust: schemas.CustomerCreate, db: Session = Depends(get_db)):
    return crud.create_customer(db=db, customer=cust)


@app.get("/customers/", response_model=list[schemas.Customer])
def get_customers(
        current_user: dict = Depends(get_current_user), skip: int = 0,
        limit: int = 100, db: Session = Depends(get_db),):
    return crud.get_customers(db, skip=skip, limit=limit)
