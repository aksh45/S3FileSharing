from fileinput import filename
from flask import Flask, render_template, session
from flask import request, Response, redirect
from flask_session import Session
import boto3
from werkzeug.utils import secure_filename
import os
import random
import base64
from flask_sqlalchemy import SQLAlchemy
import json
from flask import send_file
import os 
from dotenv import load_dotenv
import requests
import jwt
load_dotenv()


# import botocore


app = Flask(__name__)
app.config['S3_BUCKET'] = os.getenv("S3_BUCKET")
app.config['S3_KEY'] = os.getenv("S3_KEY")
app.config['S3_SECRET'] = os.getenv("S3_SECRET")
app.config['S3_LOCATION'] = f"http://{app.config['S3_BUCKET']}.s3.amazonaws.com/"
app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
s3 = boto3.client(
    's3',
    aws_access_key_id = app.config['S3_KEY'],
    aws_secret_access_key = app.config['S3_SECRET']
)

db = SQLAlchemy(app)
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)
    content_type = db.Column(db.String(130), unique=False, nullable=False)
    user_id = db.Column(db.Integer, unique=False, nullable=True)

    def __repr__(self):
        return json.dumps({"id":self.id,"FileName" : self.file_name, "Password": self.password,"ContentType": self.content_type})
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)
class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey(File.id), primary_key=True)
    shared_by = db.Column(db.Integer, db.ForeignKey(User.id), primary_key=True)
    shared_with = db.Column(db.Integer, db.ForeignKey(User.id), primary_key=True)

@app.route('/',methods = ['POST'])
def uploadFile():
    if "user_file" not in request.files:
        return "No user_file key in request.files"
    file = request.files["user_file"]
    
    if file:
        file.filename = secure_filename(file.filename)
        file.filename = f"{random.randrange(10**7,10**9)}_{file.filename}"
        output = file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        path = f"{os.path.join(app.config['UPLOAD_FOLDER'])}/{file.filename}"
        password = request.form["password"] or ''
        password = password.encode('utf-8')
        hash = base64.b64encode(password)
        if session.get("id"):
            user_id = session.get("id")
        else:
            user_id = None
        print(user_id,"my user id")
        p = File(file_name=file.filename, password=hash.decode('utf-8'), content_type=file.content_type,user_id = user_id)
        db.session.add(p)
        db.session.commit()
        db.session.refresh(p)
        s3.upload_file(
            path,
            app.config['S3_BUCKET'],
            file.filename ,
            ExtraArgs={
                "ContentType": file.content_type,
                "Tagging": f"passkey={hash.decode('utf-8')}"               # Set appropriate content type as per the file
            },
        )
        os.remove(path)
        return {"message": "success", "fileId": p.id}
    else:
        return {"message": "file is missing", "status": "error"}

@app.route('/login',methods = ['GET'])
def login():
    if session.get("id"):
        return redirect("/index")
    return redirect(f"{os.getenv('COGNITO_DOMAIN_NAME')}/login?response_type=code&client_id={os.getenv('COGNITO_CLIENT_ID')}&redirect_uri={os.getenv('COGNITO_REDIRECT_URI')}")

@app.route('/download', methods = ['GET'])
def getFile():
    if(not request.form["id"]):
        return {"status":"error","message": "id field is mandatory"}
    data = File.query.get(request.form["id"])
    
    password = request.form["pass"] or ''
    password = password.encode('utf-8')
    hash = base64.b64encode(password)
    hash = hash.decode('utf-8')
    file_share = Share.query.filter(Share.file_id == request.form["id"], Share.shared_with == session.get("id"))
    if(data == None):
        return {"status": "error","message": "invalid Id"}
    elif  not session.get("id") and data.user_id != None:
        return {"status": "Failed", "message": "You are not authorised to download this file"}
    elif(data.user_id != session.get("id") and file_share == None ):
        return {"status": "Failed", "message": "This file is neither owned by you nor shared with you"}
    
    file_dict = json.loads(str(data))
    if(file_dict["Password"] != hash):
        return {"status": "error", "message": "Invalid password"}
    file = s3.get_object(Bucket=app.config['S3_BUCKET'], Key=file_dict["FileName"])
    file_name = '_'.join(file_dict["FileName"].split('_')[1::])
    return Response(file['Body'].read(), mimetype=file_dict["ContentType"], headers={"Content-Disposition": f"attachment;filename={file_name}"})

@app.route('/logout', methods = ["GET"])
def logout():
    session.pop('id', None)
    return redirect(f'{os.getenv("COGNITO_DOMAIN_NAME")}/logout?client_id={os.getenv("COGNITO_CLIENT_ID")}&logout_uri={os.getenv("COGNITO_LOGOUT_URI")}')
@app.route('/sharefile',methods = ['POST'])
def share():
    if not session.get("id"):
        return redirect('/login')
    
    file_id = request.form["file_id"]
    shared_by = session.get("id")
    shared_with = request.form["shared_with"]
    if(not file_id or not shared_with):
        return {"status": "error","message":"file_id and shared_with are mandatory fielts"}
    data = Share.query.filter(Share.shared_by == shared_by, Share.shared_with == shared_with)
    if(data):
        return {"message": "you have already shared this file", "status":"error"}
    p = Share(file_id = file_id, shared_by=shared_by, shared_with = shared_with)
    db.session.add(p)
    db.session.commit()
    db.session.refresh(p)
    return {"status": "success"}

@app.route('/index',methods = ["GET"])
def index():
    if  not session.get("id"):
        redirect("/login")
    return "Hello you are logged in"
@app.route('/callback/auth',methods = ["GET"])
def generateAuth():
    if  session.get("id"):
        return redirect('/index')
    code = request.args["code"]
    
    access_token_res = requests.post(
        f"{os.getenv('COGNITO_DOMAIN_NAME')}/oauth2/token?grant_type=authorization_code&client_id={os.getenv('COGNITO_CLIENT_ID')}&scope=profile&code={code}&redirect_uri={os.getenv('COGNITO_REDIRECT_URI')}&client_secret={os.getenv('COGNITO_CLIENT_SECRET')}", headers={"Content-Type": "application/x-www-form-urlencoded"})
    access_token = access_token_res.json()
    print(access_token)
    id_token = access_token["id_token"]
    details = jwt.decode(id_token, options={"verify_signature": False})
    print(details)
    data = User.query.filter(User.email == details["email"]).first()
    if(data ==  None):
        p = User(email = details["email"], name = details["name"])
        db.session.add(p)
        db.session.commit()
        db.session.refresh(p)
        session["id"] = p.id
    else:
        session["id"] = data.id

    return redirect("/index")


@app.route("/callback/signout", methods = ["GET"])
def logoutCallback():
    return redirect('/login')