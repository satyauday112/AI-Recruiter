from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

fake_users = {
    'admin': {
    'username': 'admin',
    'email': 'admin@mail.com',
    'role': 'admin'},

    'recruiter':{
        'username': 'recruiter',
        'email': 'rec@email.com',
        'role': 'recruiter'},

    'jobseeker':{
        'username': 'jobseeker',
        'email':'jobseeker@email.com',
        'role': 'jobseeker'}

    }

SECRET_KEY = "83daa0256a2289b0fb23693bf1f6034d44396675749244721a2b20e896e11662"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

for id,details in fake_users.items():
    fake_users[id]['hashed_password'] = pwd_context.hash(details['role']+'password')

class Token(BaseModel):
    access_token: str
    token_type: str

class Details(BaseModel):
    username: str
    email: str
    role: str

def generate_token(username: str, password: str):
    verify = pwd_context.verify(password, fake_users[username]['hashed_password'])
    if verify:
        token = jwt.encode({'sub':username}, SECRET_KEY, algorithm=ALGORITHM)
        return token
    
    return None

@app.post('/token', response_model=Token)
def get_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint to get an access token.
    """
    
    token = generate_token(form_data.username, form_data.password)
    print("Token:", token)
    if token:
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Inactive user")
    

@app.get('/details', response_model=Details)
def get_details(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return Details(username=username, email=fake_users[username]['email'], role=fake_users[username]['role'])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
        

    