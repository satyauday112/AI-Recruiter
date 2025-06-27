from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
import datetime
from typing import List, Optional, Annotated
import db as db

SECRET_KEY = "Your Secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 45

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
db.init_db()

# for id,details in fake_users.items():
#     fake_users[id]['hashed_password'] = pwd_context.hash(details['role']+'password')

class Loginschema(BaseModel):
    username: str
    password: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserDetails(BaseModel):
    username: str
    email: str
    role: str = 'jobseeker'
    preferences: Optional[List[str]] = []
    applied_jobs: Optional[List[str]] = []

class RecruiterDetails(BaseModel):
    company_name: str
    email: str
    role: str = 'recruiter'
    posted_jobs: Optional[List[str]] = []

class user_creation_schema(BaseModel):
    username: str
    email: str
    password: str
    preferences: Optional[List[str]] = []

class recruiter_creation_schema(BaseModel):
    company_name: str
    email: str
    password: str
    role: str = 'recruiter'
    posted_jobs: Optional[List[str]] = []

def generate_token(username: str, password, hashed_password):
    verify = pwd_context.verify(password, hashed_password)
    if verify:
        token = jwt.encode({'sub':username,'exp':datetime.datetime.now(datetime.UTC)+datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
        return token
    
    return None

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")


@app.post('/token', response_model=Token)
def get_access_token(form_data: Annotated[Loginschema, Form()]):
    """
    Endpoint to get an access token.
    """
    if form_data.role not in ['jobseeker', 'recruiter', 'admin']:
        raise HTTPException(status_code=400, detail="Invalid role specified")
    
    if form_data.role == 'jobseeker':
        details = db.get_user_details(form_data.username)

    elif form_data.role == 'recruiter':
        details = db.get_recruiter_details(form_data.username)
        details['username'] = details['company_name']
    else:
        details = db.get_admin_details(form_data.username)
    
    if not details:
        raise HTTPException(status_code=404, detail="User not found")
    
    token = generate_token(details['username'], form_data.password, details['hashed_password'])
    
    if token:
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Inactive user")
    

@app.get('/userdetails', response_model=UserDetails)
def get_user_details(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user_details = db.get_user_details(username)
        return UserDetails(username=user_details['username'], 
                           email=user_details['email'], 
                           preferences=user_details['preferences'], 
                           applied_jobs=user_details['applied_jobs'])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@app.get('/recruiterdetails/',response_model=RecruiterDetails)
def get_recruiter_details(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        recruiter = payload.get("sub")
        if recruiter is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        recruiter_details = db.get_recruiter_details(recruiter)
        if recruiter_details['role'] != 'recruiter':
            raise HTTPException(status_code=403, detail="Only recruiters can view their details")
        
        return RecruiterDetails(company_name=recruiter_details['company_name'],
                                email=recruiter_details['email'],
                                posted_jobs=recruiter_details['posted_jobs'])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
@app.get('/admin_details', response_model=UserDetails)
def get_admin_details(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        adminusername = payload.get("sub")
        if adminusername is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        admin_details = db.get_admin_details(adminusername)
        if not admin_details:
            raise HTTPException(status_code=404, detail="Admin not found")
        
        return UserDetails(username=admin_details['username'], 
                           email=admin_details['email'], 
                           role='admin')
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@app.post('/create_user')
def create_user(user_details: Annotated[user_creation_schema,Form()]):
        id = db.create_user(user_details)
        if not id:
            raise HTTPException(status_code=400, detail="User creation failed")
        return {"message": "User created successfully"}

@app.get('/get_posts')
def get_posts(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user_details = db.get_user_details(username)
        
        posts = db.get_job_posts(user_details["preferences"])  # Assuming this function exists in db.py
        return posts
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
@app.post('/add_job_post')
def add_job_post(job_post: Annotated[db.Jobpost_schema, Form()], token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        rec_details = db.get_recruiter_details(username)
        if rec_details['role'] != 'recruiter':
            raise HTTPException(status_code=403, detail="Only recruiters can add job posts")
        job_post.company = rec_details["company_name"]

        post_id = db.add_job_post(job_post, job_post.company)  

        return {"message": "Job post added successfully", "post_id": post_id}
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    

@app.get('/recruiter_posts')
def get_recruiter_posts(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        recruiter = payload.get("sub")
        if recruiter is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        recruiter_details = db.get_recruiter_details(recruiter)
        if recruiter_details['role'] != 'recruiter':
            raise HTTPException(status_code=403, detail="Only recruiters can view their posts")
        
        posts = db.get_recruiter_posts(recruiter)  
        
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
@app.post('/apply_job/')
def apply_job(job_id: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user_details = db.get_user_details(username)
        if not user_details:
            raise HTTPException(status_code=403, detail="Only job seekers can apply for jobs")
        
        is_applied, message = db.apply_job(job_id, user_details['username'])  

        if not is_applied:
            raise HTTPException(status_code=400, detail=message)
        
        return {"id": message}
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
@app.get('/get_applicants/')
def get_applicants(job_id: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        recruiter = payload.get("sub")
        if recruiter is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        recruiter_details = db.get_recruiter_details(recruiter)
        if not recruiter_details:
            raise HTTPException(status_code=403, detail="Only recruiters can view applicants")
        
        applicants = db.get_applicants(job_id)  # Assuming this function exists in db.py
        return applicants
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
@app.get('/get_job_status/')
def get_job_status(job_id: str, token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user_details = db.get_user_details(username)
        if not user_details:
            raise HTTPException(status_code=403, detail="Invalid user credentials")
        
        # Logic to get the status of the job application
        # This part would depend on how you want to handle job statuses in your database
        status = db.get_job_status(job_id, user_details["username"])  # Assuming this function exists in db.py
        print("status:", status)
        return {"status": status}
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    


@app.post('/add_recruiter')
def add_recruiter(recruiter_details: Annotated[recruiter_creation_schema, Form()], token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        admin_details = db.get_admin_details(username)

        if not admin_details:
            raise HTTPException(status_code=403, detail="Only admins can add recruiters")
        
        recruiter_id = db.add_recruiter(recruiter_details)  # Assuming this function exists in db.py
        return {"message": "Recruiter added successfully", "recruiterinsertid": recruiter_id}
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
@app.get('/test')
def test():
    return {"message": "API is working!"}
