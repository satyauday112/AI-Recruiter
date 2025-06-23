import pymongo
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from datetime import datetime

DB_NAME = "AI_Recruiter"
USERS_COLLECTION = "users"
RECRUITERS_COLLECTION = "recruiters"
ADMIN_COLLECTION = "admin"
# USERS_PREFERENCES_COLLECTION = "user_preferences"
POSTS = "job_posts"
APPLICATIONS = "job_applications"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Usercol_schema(BaseModel):
    username: str
    email: str
    hashed_password: str
    preferences: Optional[List[str]] = []
    applied_jobs: Optional[List[str]] = []

class Jobpost_schema(BaseModel):
    title: str
    description: str
    company: Optional[str] = None
    location: str
    requirements: List[str]
    tags: List[str]
    salary: Optional[float] = -1

class Job_applied_candidates_schema(BaseModel):
    candidateusername: str
    score: Optional[float] = None
    hiring_status: bool = False
    rounds_attended: int = 0
    applied_on: datetime

class Job_candidates_schema(BaseModel):
    job_id: str
    details: List[Job_applied_candidates_schema]

class Recruiter_schema(BaseModel):
    company_name: str
    email: str
    hashed_password: str
    role: str = 'recruiter'
    posted_jobs: Optional[List[str]] = []

class Admin_schema(BaseModel):
    username: str
    email: str
    hashed_password: str
    role: str = 'admin'


client = pymongo.MongoClient('mongodb://localhost:27017')
db = client[DB_NAME]

def init_db():
    if ADMIN_COLLECTION not in db.list_collection_names():
        admincol = db[ADMIN_COLLECTION]
        admincol.insert_one(
        Admin_schema(
            username='admin',
            email='admin@mail.com',
            role='admin',
            hashed_password=pwd_context.hash('adminpassword')
        ).model_dump()
        )
        


def create_user(user_details):
    
    collection = db[USERS_COLLECTION]
    if collection.find_one({"username": user_details.username}):
        return "Username already exists"
    
    user_data = Usercol_schema(
        username=user_details.username,
        email=user_details.email,
        preferences=user_details.preferences,
        role='user',
        hashed_password=pwd_context.hash(user_details.password)
    )
    result = collection.insert_one(user_data.model_dump())
    
    return str(result.inserted_id)

def create_recruiter(recruiter_details):
    collection = db[RECRUITERS_COLLECTION]
    if collection.find_one({"company_name": recruiter_details.company_name}):
        raise ValueError("Company name already exists")
    
    recruiter_data = Recruiter_schema(
        company_name=recruiter_details.company_name,
        email=recruiter_details.email,
        hashed_password=pwd_context.hash(recruiter_details.password)
    )
    result = collection.insert_one(recruiter_data.model_dump())
    
    return str(result.inserted_id)


def get_user_details(username: str):
    return db[USERS_COLLECTION].find_one({'username': username})

def get_recruiter_details(companyname: str):
    recruiter = db[RECRUITERS_COLLECTION].find_one({"company_name": companyname})
    if recruiter:
        recruiter["company_name"] = str(recruiter["company_name"])
        return recruiter
    return None

def get_admin_details(adminusername: str):
    admin = db[ADMIN_COLLECTION].find_one({"username": adminusername})
    if admin:
        admin["username"] = str(admin["username"])
        return admin
    return None

def get_job_posts(preferences: List[str]):
    posts = list(db[POSTS].find({"tags": {"$in": preferences}}))
    print(preferences)
    for post in posts:
        post["_id"] = str(post["_id"])
    return posts

def add_job_post(job_post: Jobpost_schema, companyname: str):
    collection = db[POSTS]
    job_data = job_post.model_dump()
    result = collection.insert_one(job_data)

    db[RECRUITERS_COLLECTION].update_one(
        {"company_name": companyname},
        {"$push": {"posted_jobs": str(result.inserted_id)}}
    )
    return str(result.inserted_id)

def get_recruiter_posts(recruiter: str):
    posts = list(db[POSTS].find({"company": recruiter}))
    for post in posts:
        post["_id"] = str(post["_id"])
    return posts

def apply_job(job_id, username):

    if db[APPLICATIONS].find_one({"job_id": job_id,"details.candidateusername": username}):
        return False, "Already applied for this job"

    doc = db[APPLICATIONS].find_one({"job_id": job_id})
    
    if not doc:
        id = db[APPLICATIONS].insert_one(Job_candidates_schema(
            job_id=job_id, 
            details=[Job_applied_candidates_schema(candidateusername=username,applied_on=datetime.now())])
            .model_dump()
        )
        id = id.inserted_id

    else:
        print('else executing')
        id = db[APPLICATIONS].update_one({"job_id": job_id},
                             {"$push":{'details':Job_applied_candidates_schema(candidateusername=username,
                                                                               applied_on=datetime.now()
                                                                               ).model_dump()}})
        id = id.upserted_id

    db[USERS_COLLECTION].update_one(
        {"username": username},{"$push": {"applied_jobs": job_id}})

    return True, str(id)

def get_applicants(job_id: str):

    applications = list(db[APPLICATIONS].find({"job_id": job_id}))[0]['details']
    
    return applications

def get_job_status(job_id: str, candidateusername: str):
    application = db[APPLICATIONS].find_one({"job_id": job_id, 
                                             "details.candidateusername": candidateusername})['details'][0]
    
    if application:
        return {
            "status": application["hiring_status"],
            "rounds_attended": application["rounds_attended"],
            "applied_on": application["applied_on"]
        }
    return None

def add_recruiter(recruiter_details):
    collection = db[RECRUITERS_COLLECTION]
    recruiter_data = Recruiter_schema(
        company_name=recruiter_details.company_name,
        email=recruiter_details.email,
        hashed_password=pwd_context.hash(recruiter_details.password)
    )
    result = collection.insert_one(recruiter_data.model_dump())
    
    return str(result.inserted_id)

if __name__ == "__main__":
    init_db()
    print(get_user_details('admin'))