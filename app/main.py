from fileinput import filename
from flask import Flask,render_template
from flask import request, Response
import boto3
from werkzeug.utils import secure_filename
import os
import random
import base64
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, migrate
import json
from flask import send_file
import os 
from dotenv import load_dotenv
load_dotenv()


# import botocore


app = Flask(__name__)
app.config['S3_BUCKET'] = os.getenv("S3_BUCKET")
app.config['S3_KEY'] = os.getenv("S3_KEY")
app.config['S3_SECRET'] = os.getenv("S3_SECRET")
app.config['S3_LOCATION'] = f"http://{app.config['S3_BUCKET']}.s3.amazonaws.com/"
app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")

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

    def __repr__(self):
        return json.dumps({"id":self.id,"FileName" : self.file_name, "Password": self.password,"ContentType": self.content_type})



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
        password = request.form["password"]
        password = password.encode('utf-8')
        hash = base64.b64encode(password)
        p = File(file_name=file.filename, password=hash.decode('utf-8'), content_type=file.content_type)
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


@app.route('/download', methods=['GET'])
def getFile():
    data = File.query.get(request.form["id"])
    
    password = request.form["pass"]
    password = password.encode('utf-8')
    hash = base64.b64encode(password)
    hash = hash.decode('utf-8')
    if(data == None):
        return {"status": "error","message": "invalid Id"}
    file_dict = json.loads(str(data))
    if(file_dict["Password"] != hash):
        return {"status": "error", "message": "Invalid password"}
    file = s3.get_object(Bucket=app.config['S3_BUCKET'], Key=file_dict["FileName"])
    file_name = '_'.join(file_dict["FileName"].split('_')[1::])
    return Response(file['Body'].read(), mimetype=file_dict["ContentType"], headers={"Content-Disposition": f"attachment;filename={file_name}"})

