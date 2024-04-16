from flask import Flask, session
from flask import jsonify
import boto3
import botocore
from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets import SecretClient
import traceback
from packaging import version
from flask import Flask, render_template, url_for, flash, redirect, request
import requests
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from decouple import config
from flask_cors import CORS
from google.cloud import container_v1
from googleapiclient import discovery
from google.oauth2 import service_account
import mysql.connector
import pytz
from azure.mgmt.keyvault import KeyVaultManagementClient

from azure.mgmt.resource import ResourceManagementClient
from azure.core.exceptions import HttpResponseError
import time
import os
import subprocess
import random
import base64
from azure.mgmt.containerservice import ContainerServiceClient
from upload_tf_file import upload_file_to_gitlab
import json
from azure.identity import ClientSecretCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from flask import Flask, jsonify
import hcl
import re 
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import gitlab
import concurrent.futures
from gitlab.exceptions import GitlabAuthenticationError, GitlabGetError, GitlabListError
from datetime import datetime
from oauthlib.oauth2 import WebApplicationClient
from dotenv import load_dotenv


os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

gitlab_url = "https://gitlab.com"
project_id = "51819357"
access_token = "glpat-LryS1Hu_2ZX17MSGhgkz"    
branch_name = "featurebrach1"
app = Flask(__name__, static_url_path='/static')

CORS(app) 

app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

app.config['WTF_CSRF_ENABLED'] = False

load_dotenv()
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:cockpitpro@4.188.187.102:3306/jobinfo'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

client = WebApplicationClient(GOOGLE_CLIENT_ID)
 
class UserAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    account_name = db.Column(db.String(255), nullable=False)
    cloud_name = db.Column(db.String(255), nullable=False)
class UsernameTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"UsernameTable('{self.username}')"
class UsernameTableaws(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"UsernameTable('{self.username}')"
class UsernameTablegcp(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"UsernameTable('{self.username}')"
    
    
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False, default='default_password')
    token = db.Column(db.String(120))
    provider = db.Column(db.String(30), nullable=False, default='self_provider')
    todo = db.relationship('todo', backref='items', lazy=True)
    
    def is_google_provider(self):
        if self.provider == 'google':
            return True
    
    def get_auth_token(self):
        return self.token
 
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    
    
class aks_cluster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    cloudname = db.Column(db.String(255), nullable=False)
    resource_group = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(255), nullable=False)
    aks_name = db.Column(db.String(255), nullable=False)
    def __repr__(self):
        return f"aks_cluster('{self.username}')"
class eks_cluster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    cloudname = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(255), nullable=False)
    eks_name = db.Column(db.String(255), nullable=False)
    def __repr__(self):
        return f"eks_cluster('{self.username}')"
class gke_cluster(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    cloudname = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(255), nullable=False)
    eks_name = db.Column(db.String(255), nullable=False)
    def __repr__(self):
        return f"gke_cluster('{self.username}')"
class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    cloudname = db.Column(db.String(20), nullable=False)
    clustername = db.Column(db.String(20), nullable=False)
 
class todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    complete=db.Column(db.Boolean,default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
 
    def __repr__(self):
        return f"todo('{self.content}', '{self.date_posted}')"
 
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(min=3, max=20)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
 
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('username already exist. Please choose a different one.')
 
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('email already exist. Please choose a different one.')



def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route('/google/login')
def google_login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    print(request_uri)
    return redirect(request_uri)

@app.route("/google/login/callback")
def callback():
    
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Getting token_endpoint from Google
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send request to get tokens
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    # client.parse_request_body_response(json.dumps(token_response.json()))
    tokens = client.parse_request_body_response(json.dumps(token_response.json()))
    access_token = tokens.get('access_token')

    # Hitting URL to get user's information from Google
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # Check for verified email address
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        # picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in our db with the information provided by Google
    user = User(username=users_name, email=users_email, token=access_token, provider='google')

    # Doesn't exist? Then add and commit to database
    if not User.query.filter_by(email=users_email).first():
        db.session.add(user)
        db.session.commit()

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to dashboard
    return redirect(url_for("dashboard"))

# @app.route("/google/logout")
# @login_required
# def google_logout():
#     logout_user()
#     return redirect(url_for("home"))

def RegistrationJSONForm(data):
    #print(data['username'])
    user = User.query.filter_by(username=data['username']).first()
    email = User.query.filter_by(username=data['email']).first()
    if user or email:
        return 0
    return 1
    
class LoginForm(FlaskForm):
    email = StringField('Email',
    validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
 
 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
 
 
@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')
 
def get_authenticated_user_id():
    username = session.get('username')
    return username


@app.route('/recentjob_azure', methods=['GET'])
def recentjob_azure():
    username = current_user.username
    job_name = 'azure_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
 
    # Get the most recent job ID
    if job_ids:
        most_recent_job_id = max(job_ids)
        return redirect(url_for('logs_azure', job_id=most_recent_job_id))
 
    return render_template('jobs_azure.html', outputs=[])
 
 
@app.route('/json_recentjob_azure', methods=['POST'])
def json_recentjob_azure():
    form = request.get_json()
    username = form['username']
    job_name = 'azure_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
 
    # Get the most recent job ID
    if job_ids:
        most_recent_job_id = max(job_ids)
        response_data = {
                'username': username,
                'most_recent_job_id': most_recent_job_id,
                'message': 'Most recent job ID retrieved successfully'
            }
 
        return jsonify(response_data)
 
    # return render_template('jobs_azure.html', outputs=[])
 
@app.route('/recentjoblogs-azure', methods=['GET', 'POST'])
def recentjoblogs_azure():
    if current_user.is_authenticated:
        username = current_user.username
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job_id')
 
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}
 
        response = requests.get(job_url, headers=headers)
 
        for job in response.json():
 
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
 
            log_response = requests.get(log_url, headers=headers)
 
            log_data = log_response.text
 
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
 
 
        clean_logs = ansi_escape.sub('', log_data)
 
 
        return render_template('logs-azure.html', username=username, logs=clean_logs)
    else:
        return redirect(url_for('login'))
 
@app.route('/json-recentjoblogs-azure', methods=['GET', 'POST'])
def json_recentjoblogs_azure():
        form = request.get_json()
        username = form['username']
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job_id')
 
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}
 
        response = requests.get(job_url, headers=headers)
 
        for job in response.json():
 
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
 
            log_response = requests.get(log_url, headers=headers)
 
            log_data = log_response.text
 
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
 
 
        clean_logs = ansi_escape.sub('', log_data)
        response_data = {
                'username': username,
                'logs': clean_logs
            }
 
        return jsonify(response_data)



@app.route('/recentjob_aws', methods=['GET'])
def recentjob_aws():
    username = current_user.username
    job_name = 'aws_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
 
    # Get the most recent job ID
    if job_ids:
        most_recent_job_id = max(job_ids)
        return redirect(url_for('logs_aws', job_id=most_recent_job_id))
 
    return render_template('jobs_aws.html', outputs=[])
 
 
@app.route('/json_recentjob_aws', methods=['POST'])
def json_recentjob_aws():
    form = request.get_json()
    username = form['username']
    job_name = 'aws_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
 
    # Get the most recent job ID
    if job_ids:
        most_recent_job_id = max(job_ids)
        response_data = {
                'username': username,
                'most_recent_job_id': most_recent_job_id,
                'message': 'Most recent job ID retrieved successfully'
            }
 
        return jsonify(response_data)
 
    # return render_template('jobs_azure.html', outputs=[])
 
@app.route('/recentjoblogs-aws', methods=['GET', 'POST'])
def recentjoblogs_aws():
    if current_user.is_authenticated:
        username = current_user.username
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job_id')
 
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}
 
        response = requests.get(job_url, headers=headers)
 
        for job in response.json():
 
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
 
            log_response = requests.get(log_url, headers=headers)
 
            log_data = log_response.text
 
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
 
 
        clean_logs = ansi_escape.sub('', log_data)
 
 
        return render_template('logs-aws.html', username=username, logs=clean_logs)
    else:
        return redirect(url_for('login'))
 
@app.route('/json-recentjoblogs-aws', methods=['GET', 'POST'])
def json_recentjoblogs_aws():
        form = request.get_json()
        username = form['username']
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job_id')
 
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}
 
        response = requests.get(job_url, headers=headers)
 
        for job in response.json():
 
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
 
            log_response = requests.get(log_url, headers=headers)
 
            log_data = log_response.text
 
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
 
 
        clean_logs = ansi_escape.sub('', log_data)
        response_data = {
                'username': username,
                'logs': clean_logs
            }
 
        return jsonify(response_data)


@app.route('/recentjob_gcp', methods=['GET'])
def recentjob_gcp():
    username = current_user.username
    job_name = 'gcp_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
 
    # Get the most recent job ID
    if job_ids:
        most_recent_job_id = max(job_ids)
        return redirect(url_for('logs_gcp', job_id=most_recent_job_id))
 
    return render_template('jobs_gcp.html', outputs=[])
 
 
@app.route('/json_recentjob_gcp', methods=['POST'])
def json_recentjob_gcp():
    form = request.get_json()
    username = form['username']
    job_name = 'gcp_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
 
    # Get the most recent job ID
    if job_ids:
        most_recent_job_id = max(job_ids)
        response_data = {
                'username': username,
                'most_recent_job_id': most_recent_job_id,
                'message': 'Most recent job ID retrieved successfully'
            }
 
        return jsonify(response_data)
 
    # return render_template('jobs_azure.html', outputs=[])
 
@app.route('/recentjoblogs-gcp', methods=['GET', 'POST'])
def recentjoblogs_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job_id')
 
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}
 
        response = requests.get(job_url, headers=headers)
 
        for job in response.json():
 
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
 
            log_response = requests.get(log_url, headers=headers)
 
            log_data = log_response.text
 
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
 
 
        clean_logs = ansi_escape.sub('', log_data)
 
 
        return render_template('logs-gcp.html', username=username, logs=clean_logs)
    else:
        return redirect(url_for('login'))
 
@app.route('/json-recentjoblogs-gcp', methods=['GET', 'POST'])
def json_recentjoblogs_gcp():
        form = request.get_json()
        username = form['username']
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job_id')
 
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}
 
        response = requests.get(job_url, headers=headers)
 
        for job in response.json():
 
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
 
            log_response = requests.get(log_url, headers=headers)
 
            log_data = log_response.text
 
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
 
 
        clean_logs = ansi_escape.sub('', log_data)
        response_data = {
                'username': username,
                'logs': clean_logs
            }
 
        return jsonify(response_data)


@app.route('/jobs_aws', methods=['GET'])
def jobs_aws():
        username = current_user.username
        job_name = 'aws_infrastructure'
 
        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }
 
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
 
        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]
 
        # Close the database connection
        cursor.close()
        connection.close()
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
        
        project = gl.projects.get(project_id)
        outputs = []
        for job_id in job_ids:
        # Get the job details
            job = project.jobs.get(job_id)
            
            # Get the job details
            created_at = job.created_at
            utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
            utc_time = utc_time.replace(tzinfo=pytz.UTC)
            ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
            created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')        
            status = job.status
            output = f"Created At: {created_at_str}, Created By: {username}, eks Status: {status}, Job Name: {job_name}, Job ID: <a href='/logs-azure?job-id={job_id}'>{job_id}</a>"
            outputs.append(output)
            print(output)
 
        final_job = []
        final_job= sorted(outputs, reverse=True)
        return render_template('jobs_aws.html', outputs=outputs)
 
@app.route('/json_jobs_aws', methods=['POST'])
def json_jobs_aws():
    form = request.get_json()
    username = form['username']
    job_name = 'aws_infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'aws_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
    outputs = []
 
    for job_id in job_ids:
        # Get the job details
        job = project.jobs.get(job_id)
 
        # Get the job details
        created_at = job.created_at
        utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
        utc_time = utc_time.replace(tzinfo=pytz.UTC)
        ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
        created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')        
        status = job.status
 
        output = {
            "created_at": created_at_str,
            "created_by": username,
            "eks_status": status,
            "job_name": job_name,
            "job_id": job_id,
            "job_link": f"/logs-azure?job-id={job_id}"
        }
        outputs.append(output)
        print(output)
 
    final_job = sorted(outputs, key=lambda x: x['created_at'], reverse=True)
 
    # Returning JSON response
    return jsonify(final_job)
 
 
 
@app.route('/jobs_aws_delete', methods=['GET'])
def jobs_aws_delete():
        username = current_user.username
        job_name = 'delete_aws_infrastructure'
 
        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }
 
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
 
        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]
 
        # Close the database connection
        cursor.close()
        connection.close()
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
        
        project = gl.projects.get(project_id)
        outputs = []
        for job_id in job_ids:
        # Get the job details
            job = project.jobs.get(job_id)
            
            # Get the job details
            created_at = job.created_at
            utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
            utc_time = utc_time.replace(tzinfo=pytz.UTC)
            ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
            created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')
            status = job.status
            output = f"Created At: {created_at_str}, Created By: {username}, AKS Status: {status}, Job Name: {job_name}, Job ID: <a href='/logs-azure?job-id={job_id}'>{job_id}</a>"
            outputs.append(output)
            print(output)
 
        final_job = []
        final_job= sorted(outputs, reverse=True)
        return render_template('jobs_aws.html', outputs=outputs)




 
@app.route('/json_jobs_aws_delete', methods=['POST'])
def json_jobs_aws_delete():
    form = request.get_json()
    username = form['username']
    job_name = 'delete-aws-infrastructure'
 
    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }
 
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
 
    # Fetch job IDs for username 'jini' and job_name 'aws_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]
 
    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
 
    project = gl.projects.get(project_id)
    outputs = []
 
    for job_id in job_ids:
        # Get the job details
        job = project.jobs.get(job_id)
 
        # Get the job details
        created_at = job.created_at
        utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
        utc_time = utc_time.replace(tzinfo=pytz.UTC)
        ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
        created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')
        status = job.status
 
        output = {
            "created_at": created_at_str,
            "created_by": username,
            "eks_status": status,
            "job_name": job_name,
            "job_id": job_id,
            "job_link": f"/logs-azure?job-id={job_id}"
        }
        outputs.append(output)
        print(output)
 
    final_job = sorted(outputs, key=lambda x: x['created_at'], reverse=True)
 
    # Returning JSON response
    return jsonify(final_job)


@app.route('/jobs_azure', methods=['GET'])
def jobs_azure():
        username = current_user.username 
        job_name = 'azure_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

        
        project = gl.projects.get(project_id)
        outputs = []
        for job_id in job_ids:
        # Get the job details
            job = project.jobs.get(job_id)
            
            # Get the job details
            created_at = job.created_at
            utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
            utc_time = utc_time.replace(tzinfo=pytz.UTC)
            ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
            created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')            
            status = job.status
            output = f"Created At: {created_at_str}, Created By: {username}, AKS Status: {status}, Job Name: {job_name}, Job ID: <a href='/logs-azure?job-id={job_id}'>{job_id}</a>"
            outputs.append(output)
            print(output)

        final_job = []
        final_job= sorted(outputs, reverse=True)
        return render_template('jobs_azure.html', outputs=final_job)

@app.route('/json_jobs_azure', methods=['POST'])
def json_jobs_azure():
    form = request.get_json()
    username = form['username']
    job_name = 'azure_infrastructure'

    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]

    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

    project = gl.projects.get(project_id)
    outputs = []
    
    for job_id in job_ids:
        # Get the job details
        job = project.jobs.get(job_id)
        
        # Get the job details
        created_at = job.created_at
        utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
        utc_time = utc_time.replace(tzinfo=pytz.UTC)
        ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
        created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')            
        status = job.status
        
        output = {
            "created_at": created_at_str,
            "created_by": username,
            "aks_status": status,
            "job_name": job_name,
            "job_id": job_id,
            "job_link": f"/logs-azure?job-id={job_id}"
        }
        outputs.append(output)
        print(output)

    final_job = sorted(outputs, key=lambda x: x['created_at'], reverse=True)
    
    # Returning JSON response
    return jsonify(final_job)


@app.route('/jobs_azure_delete', methods=['GET'])
def jobs_azure_delete():
        username = current_user.username 
        job_name = 'delete-azure-infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

        
        project = gl.projects.get(project_id)
        outputs = []
        for job_id in job_ids:
        # Get the job details
            job = project.jobs.get(job_id)
            
            # Get the job details
            created_at = job.created_at
            utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
            utc_time = utc_time.replace(tzinfo=pytz.UTC)
            ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
            created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')            
            status = job.status
            output = f"Created At: {created_at_str}, Created By: {username}, AKS Status: {status}, Job Name: {job_name}, Job ID: <a href='/logs-azure?job-id={job_id}'>{job_id}</a>"
            outputs.append(output)
            print(output)

        final_job = []
        final_job= sorted(outputs, reverse=True)
        return render_template('jobs_azure.html', outputs=final_job)

@app.route('/json_jobs_azure_delete', methods=['POST'])
def json_jobs_azure_delete():
    form = request.get_json()
    username = form['username']
    job_name = 'delete-azure-infrastructure'

    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]

    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

    project = gl.projects.get(project_id)
    outputs = []
    
    for job_id in job_ids:
        # Get the job details
        job = project.jobs.get(job_id)
        
        # Get the job details
        created_at = job.created_at
        utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
        utc_time = utc_time.replace(tzinfo=pytz.UTC)
        ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
        created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')            
        status = job.status
        
        output = {
            "created_at": created_at_str,
            "created_by": username,
            "aks_status": status,
            "job_name": job_name,
            "job_id": job_id,
            "job_link": f"/logs-azure?job-id={job_id}"
        }
        outputs.append(output)
        print(output)

    final_job = sorted(outputs, key=lambda x: x['created_at'], reverse=True)
    
    # Returning JSON response
    return jsonify(final_job)


@app.route('/jobs_gcp', methods=['GET'])
def jobs_gcp():
        username = current_user.username
        job_name = 'gcp_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

        
        project = gl.projects.get(project_id)
        outputs = []
        for job_id in job_ids:
        # Get the job details
            job = project.jobs.get(job_id)
            
            # Get the job details
            created_at = job.created_at
            utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
            utc_time = utc_time.replace(tzinfo=pytz.UTC)
            ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
            created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')            
            status = job.status
            output = f"Created At: {created_at_str}, Created By: {username}, AKS Status: {status}, Job Name: {job_name}, Job ID: <a href='/logs-azure?job-id={job_id}'>{job_id}</a>"
            outputs.append(output)
            print(output)

        final_job = []
        final_job= sorted(outputs, reverse=True)
        
        return render_template('jobs_gcp.html', outputs=outputs)

@app.route('/json_jobs_gcp', methods=['POST'])
def json_jobs_gcp():
    form = request.get_json()
    username = form['username']
    job_name = 'gcp_infrastructure'

    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Fetch job IDs for username 'jini' and job_name 'gcp_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]

    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

    project = gl.projects.get(project_id)
    outputs = []

    for job_id in job_ids:
        # Get the job details
        job = project.jobs.get(job_id)

        # Get the job details
        created_at = job.created_at
        utc_time = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ')
        utc_time = utc_time.replace(tzinfo=pytz.UTC)
        ist_time = utc_time.astimezone(pytz.timezone('Asia/Kolkata'))
        created_at_str = ist_time.strftime('%Y-%m-%d %H:%M:%S')            
        status = job.status

        output = {
            "created_at": created_at_str,
            "created_by": username,
            "aks_status": status,
            "job_name": job_name,
            "job_id": job_id,
            "job_link": f"/logs-azure?job-id={job_id}"
        }
        outputs.append(output)
        print(output)

    final_job = sorted(outputs, key=lambda x: x['created_at'], reverse=True)

    # Returning JSON response
    return jsonify(final_job)



@app.route('/jobs_gcp_delete', methods=['GET'])
def jobs_gcp_delete():
        username = current_user.username
        job_name = 'gcp_delete_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()
        gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

        
        project = gl.projects.get(project_id)
        outputs = []
        for job_id in job_ids:
        # Get the job details
            job = project.jobs.get(job_id)
            
            # Get the job details
            created_at = job.created_at
            created_at_str = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')
            status = job.status
            output = f"Created At: {created_at_str}, Created By: {username}, AKS Status: {status}, Job Name: {job_name}, Job ID: <a href='/logs-azure?job-id={job_id}'>{job_id}</a>"
            outputs.append(output)
            print(output)

        final_job = []
        final_job= sorted(outputs, reverse=True)
        
        return render_template('jobs_gcp.html', outputs=outputs)

@app.route('/json_jobs_gcp_delete', methods=['POST'])
def json_jobs_gcp_delete():
    form = request.get_json()
    username = form['username']
    job_name = 'delete-gke-infrastructure'

    db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
    }

    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()

    # Fetch job IDs for username 'jini' and job_name 'gcp_infrastructure'
    query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
    cursor.execute(query)
    job_ids = [result[0] for result in cursor.fetchall()]

    # Close the database connection
    cursor.close()
    connection.close()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)

    project = gl.projects.get(project_id)
    outputs = []

    for job_id in job_ids:
        # Get the job details
        job = project.jobs.get(job_id)

        # Get the job details
        created_at = job.created_at
        created_at_str = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')
        status = job.status

        output = {
            "created_at": created_at_str,
            "created_by": username,
            "aks_status": status,
            "job_name": job_name,
            "job_id": job_id,
            "job_link": f"/logs-azure?job-id={job_id}"
        }
        outputs.append(output)
        print(output)

    final_job = sorted(outputs, key=lambda x: x['created_at'], reverse=True)

    # Returning JSON response
    return jsonify(final_job)


@app.route('/connect-to-cluster-gcp')
def connect_to_cluster_gcp():
    return render_template('connect-to-cluster-gcp.html') 

@app.route('/connect-to-cluster-aws')
def connect_to_cluster_aws():
    return render_template('connect-to-cluster-aws.html')

@app.route('/connect-to-cluster-az')
def connect_to_cluster_az():
    return render_template('connect-to-cluster-az.html')

@app.route('/final-dashboard', methods=['GET', 'POST'])
def dashboard():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('final-dashboard.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/dashboard-cloud', methods=['GET', 'POST'])
def dashboard_cloud():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('dashboard-cloud.html', username=username)
    else:
        return redirect(url_for('login'))
@app.route('/show-details-aws', methods=['GET', 'POST'])
def show_details_aws():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'aws')
        return render_template('show-details-aws.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))
@app.route('/json_get_credential_aws', methods=['GET', 'POST'])
def json_get_credential_aws():
    try:
        form_data = request.get_json()
        account_name = form_data['account_name']
       
        key_vault_name = account_name+"aws"
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Credential not found."}
            return jsonify(error_msg), 200
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret containing your Azure credentials
        secret_access_key = secret_client.get_secret("secret-Access-key").value
        access_key = secret_client.get_secret("Access-key").value
        response_data = {
            "secret_Access_key": secret_access_key,
            "Access_key": access_key
        }
        return jsonify(response_data), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "accounts are not avilable."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/get_credential_aws', methods=['GET', 'POST'])
def get_credential_aws():
    if current_user.is_authenticated:
        username = current_user.username
        account_name = request.form.get('account_name')
        accounts = get_account(username,'aws')
        key_vault_name = account_name+"aws"
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            return render_template('show-details-aws.html', message="credential not found",username=username,accounts=accounts)
        # Use DefaultAzureCredential to automatically authenticate
        #credential = DefaultAzureCredential()
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        secret_access_key = secret_client.get_secret("secret-Access-key").value
        access_key = secret_client.get_secret("Access-key").value
        return render_template('show-details-aws.html', username=username,accounts=accounts,access_key=access_key, secret_access_key=secret_access_key)
        
    else:
        return redirect(url_for('login'))
   

def export_azure_credentials():
    os.environ["AZURE_CLIENT_ID"] = "ad3b9e95-c03c-4728-840e-cbd8c75ea353"
    os.environ["AZURE_CLIENT_SECRET"] = "p268Q~SIJlP6FViKhI.M4B6d7dB5Tr95PZHYqczI"
    os.environ["AZURE_TENANT_ID"] = "097b85e8-2f0c-4726-a9d5-af15f7621ce5"
    os.environ["AZURE_SUBSCRIPTION_ID"] = "f1aed9cb-fcad-472f-b14a-b1a0223fa5a5"
export_azure_credentials()

def check_key_vault_existence(subscription_id, resource_group_name, key_vault_name):
    # Authenticate using DefaultAzureCredential
    credential = DefaultAzureCredential()

    # Create Key Vault Management Client
    keyvault_management_client = KeyVaultManagementClient(credential, subscription_id)

    # Check if Key Vault exists
    try:
        keyvault_management_client.vaults.get(resource_group_name, key_vault_name)
        return True  # Key Vault exists
    except HttpResponseError as ex:
        if ex.status_code == 404:
            return False  # Key Vault does not exist
        else:
            # Handle other HTTP response errors if needed
            raise

@app.route('/json-show-details-aws', methods=['POST'])
def json_show_details_aws():
    try:
        form_data = request.get_json()
        username = form_data['username']
        accounts = get_account(username,'aws')
        return jsonify(accounts), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "accounts are not avilable."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/json_get_credential', methods=['GET', 'POST'])
def json_get_credential():
    try:
        form_data = request.get_json()
        account_name = form_data['account_name']
       
        key_vault_name = account_name+"azure"
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Credential not found."}
            return jsonify(error_msg), 200
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret containing your Azure credentials
        secret_id = "client-id"
        secret_secret = "client-secret"
        secret_subscription = "subscription-id"
        secret_tenant = "tenant-id"

        client_id = secret_client.get_secret(secret_id).value
        client_secret = secret_client.get_secret(secret_secret).value
        subscription_id = secret_client.get_secret(secret_subscription).value
        tenant_id = secret_client.get_secret(secret_tenant).value
        response_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "subscription_id": subscription_id,
            "tenant_id": tenant_id
        }
        return jsonify(response_data), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "accounts are not avilable."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
    
@app.route('/get_credential', methods=['GET', 'POST'])
def get_credential():
    if current_user.is_authenticated:
        username = current_user.username
        account_name = request.form.get('account_name')
        accounts = get_account(username,'azure')
        key_vault_name = account_name+"azure"
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            return render_template('show-details-azure.html', message="credential not found",username=username,accounts=accounts)
        # Use DefaultAzureCredential to automatically authenticate
        #credential = DefaultAzureCredential()
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret containing your Azure credentials
        secret_id = "client-id"
        secret_secret = "client-secret"
        secret_subscription = "subscription-id"
        secret_tenant = "tenant-id"

        client_id = secret_client.get_secret(secret_id).value
        client_secret = secret_client.get_secret(secret_secret).value
        subscription_id = secret_client.get_secret(secret_subscription).value
        tenant_id = secret_client.get_secret(secret_tenant).value
        return render_template('show-details-azure.html', username=username,accounts=accounts,client_id=client_id, client_secret=client_secret, subscription_id=subscription_id, tenant_id=tenant_id)
        
    else:
        return redirect(url_for('login'))
@app.route('/show-details-azure', methods=['GET', 'POST'])
def show_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'azure')
        return render_template('show-details-azure.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))


@app.route('/json-show-details-azure', methods=['POST'])
def json_show_details_azure():
    try:
        form_data = request.get_json()
        username = form_data['username']
        accounts = get_account(username,'azure')
        return jsonify(accounts), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "accounts are not avilable."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/show-details-gcp', methods=['GET', 'POST'])
def show_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'gcp')
        return render_template('show-details-gcp.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))
@app.route('/get_credential_gcp', methods=['GET', 'POST'])
def get_credential_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        account_name = request.form.get('account_name')
        accounts = get_account(username,'gcp')
        key_vault_name = account_name+"gcp"
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            return render_template('show-details-gcp.html', message="credential not found",username=username,accounts=accounts)
        # Use DefaultAzureCredential to automatically authenticate
        #credential = DefaultAzureCredential()
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        secret_name = "your-secret-name"
        secret = secret_client.get_secret(secret_name)
        secret_value = secret.value
        return render_template('show-details-gcp.html', username=username,accounts=accounts,secret_value=secret_value)
        
    else:
        return redirect(url_for('login'))

@app.route('/json-show-details-gcp', methods=['POST'])
def json_show_details_gcp():
    try:
        form_data = request.get_json()
        username = form_data['username']
        accounts = get_account(username,'gcp')
        return jsonify(accounts), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "accounts are not avilable."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/json_get_credential_gcp', methods=['GET', 'POST'])
def json_get_credential_gcp():
    try:
        form_data = request.get_json()
        account_name = form_data['account_name']
       
        key_vault_name = account_name+"gcp"
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Credential not found."}
            return jsonify(error_msg), 200
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret containing your Azure credentials
        secret_name = "your-secret-name"
        secret = secret_client.get_secret(secret_name)
        secret_value = secret.value
        response_data = {
            "secret_value": secret_value
        }
        return jsonify(response_data), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "accounts are not avilable."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500


@app.route('/create-cluster', methods=['GET', 'POST'])
def create_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('create-cluster.html', username=username)
    else:
        return redirect(url_for('login'))



@app.route('/my-cluster', methods=['GET', 'POST'])
def my_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('my-cluster.html', username=username)
    else:
        return redirect(url_for('login'))


@app.route('/json-my-cluster-details-aws', methods=['POST'])
def json_my_cluster_details_aws():
    form = request.get_json()
    account = form['account_name']

    try:
        # Query the database to get AKS cluster names for the given username
        eks_names = get_cluster_aws(account)

        # Check if there are no AKS clusters available
        if not eks_names:
            return jsonify({"message": "No EKS clusters available for the given user."}), 200

        # Return JSON response with AKS cluster names
        return jsonify({"eks_cluster": eks_names}), 200

    except Exception as e:
        # Handle other exceptions (e.g., database connection error)
        print(f"Error: {str(e)}")
        return jsonify({"error_message": "An error occurred while fetching EKS cluster details."}), 500
@app.route('/my-cluster-details', methods=['GET', 'POST'])
def my_cluster_details():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('my-cluster-details.html', username=username)
    else:
        return redirect(url_for('login'))



        
@app.route('/get_azure_cluster', methods=['GET', 'POST'])
def get_azure_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        account = request.form.get('account_name')
       

        try:
            # Retrieve credentials from Azure Key Vault
            aks_names = get_cluster_azure(account)

            return render_template('my-cluster-details-azure.html', username=username,aks_clusters=aks_names)
        except Exception as e:
            print(f"Error: {str(e)}")
            # Handle the exception appropriately, e.g., return an error page
            return render_template('error.html', error_message=str(e))
    else:
        return redirect(url_for('login'))
@app.route('/get_aws_cluster', methods=['GET', 'POST'])
def get_aws_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        account = request.form.get('account_name')
       

        try:
            # Retrieve credentials from Azure Key Vault
            eks_names = get_cluster_aws(account)

            return render_template('my-cluster-details-aws.html', username=username,eks_clusters=eks_names)
        except Exception as e:
            print(f"Error: {str(e)}")
            # Handle the exception appropriately, e.g., return an error page
            return render_template('error.html', error_message=str(e))
    else:
        return redirect(url_for('login'))
def get_cluster_azure(account_name):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
    
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = f"SELECT distinct aks_name FROM aks_cluster WHERE username = '{account_name}'"
        cursor.execute(query)
        name = [result[0] for result in cursor.fetchall()]
        cursor.close()
        connection.close()
        return name
def get_cluster_aws(account_name):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
    
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = f"SELECT distinct eks_name FROM eks_cluster WHERE username = '{account_name}'"
        cursor.execute(query)
        name = [result[0] for result in cursor.fetchall()]
        cursor.close()
        connection.close()
        return name

@app.route('/my-cluster-details-azure', methods=['GET', 'POST'])
def my_cluster_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'azure')
    
            

        return render_template('my-cluster-details-azure.html', username=username,accounts=accounts)

    else:
        return redirect(url_for('login'))
@app.route('/my-cluster-details-aws', methods=['GET', 'POST'])
def my_cluster_details_aws():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'aws')
    
            

        return render_template('my-cluster-details-aws.html', username=username,accounts=accounts)

    else:
        return redirect(url_for('login'))


   


@app.route('/json-my-cluster-details-azure', methods=['POST'])
def json_my_cluster_details_azure():
    form = request.get_json()
    account = form['account_name']

    try:
        # Query the database to get AKS cluster names for the given username
        aks_names = get_cluster_azure(account)

        # Check if there are no AKS clusters available
        if not aks_names:
            return jsonify({"message": "No AKS clusters available for the given user."}), 200

        # Return JSON response with AKS cluster names
        return jsonify({"aks_cluster": aks_names}), 200

    except Exception as e:
        # Handle other exceptions (e.g., database connection error)
        print(f"Error: {str(e)}")
        return jsonify({"error_message": "An error occurred while fetching AKS cluster details."}), 500
@app.route('/json-my-cluster-details-gcp', methods=['POST'])
def json_my_cluster_details_gcp():
    form = request.get_json()
    account = form['account_name']

    try:
        # Query the database to get AKS cluster names for the given username
        gke_names = get_cluster_gcp(account)

        # Check if there are no AKS clusters available
        if not gke_names:
            return jsonify({"message": "No GKE clusters available for the given user."}), 200

        # Return JSON response with AKS cluster names
        return jsonify({"gke_cluster": gke_names}), 200

    except Exception as e:
        # Handle other exceptions (e.g., database connection error)
        print(f"Error: {str(e)}")
        return jsonify({"error_message": "An error occurred while fetching GKE cluster details."}), 500


@app.route('/my-cluster-details-gcp', methods=['GET', 'POST'])
def my_cluster_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'gcp')
    
            

        return render_template('my-cluster-details-gcp.html', username=username,accounts=accounts)

    else:
        return redirect(url_for('login'))
def get_cluster_gcp(account_name):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
    
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = f"SELECT distinct eks_name FROM gke_cluster WHERE username = '{account_name}'"
        cursor.execute(query)
        name = [result[0] for result in cursor.fetchall()]
        cursor.close()
        connection.close()
        return name
@app.route('/get_gcp_cluster', methods=['GET', 'POST'])
def get_gcp_cluster():
    if current_user.is_authenticated:
        username = current_user.username
        account = request.form.get('account_name')
       

        try:
            # Retrieve credentials from Azure Key Vault
            aks_names = get_cluster_gcp(account)

            return render_template('my-cluster-details-gcp.html', username=username,clusters=aks_names)
        except Exception as e:
            print(f"Error: {str(e)}")
            # Handle the exception appropriately, e.g., return an error page
            return render_template('error.html', error_message=str(e))
    else:
        return redirect(url_for('login'))


@app.route('/cluster-creation-status', methods=['GET', 'POST'])
def cluster_creation_status():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('cluster-creation-status.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/creation-status-aws', methods=['GET', 'POST'])
def creation_status_aws():
    if current_user.is_authenticated:
        username = current_user.username
        job_name = 'aws_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()

        return render_template('cluster-details.html', username=username, job_ids=job_ids)
    else:
        return redirect(url_for('login'))

@app.route('/json-creation-status-aws', methods=['POST'])
def json_creation_status_aws():
        form = request.get_json()
        username = form['username']
        job_name = 'aws_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()

        return jsonify({"username": username, "job_ids": job_ids}), 200


@app.route('/logs-aws', methods=['GET', 'POST'])
def logs_aws():
    if current_user.is_authenticated:
        username = current_user.username
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job-id')
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}

        response = requests.get(job_url, headers=headers)

        for job in response.json():
            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'

            log_response = requests.get(log_url, headers=headers)

            log_data = log_response.text


        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

        clean_logs = ansi_escape.sub('', log_data)


        return render_template('logs-aws.html', username=username, logs=clean_logs)
    else:
        return redirect(url_for('login'))


@app.route('/json-logs-aws', methods=['POST'])
def json_logs_aws():
        form = request.get_json()
        username = form['username']
        job_id = form['job_id']
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}

        response = requests.get(job_url, headers=headers)

    #    if response.status_code == 200:
            # Assuming response.json() returns a dictionary
        job_info = response.json()

        log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
        log_response = requests.get(log_url, headers=headers)

      #  if log_response.status_code == 200:
        log_data = log_response.text

        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        clean_logs = ansi_escape.sub('', log_data)

               # Return a JSON response
        return jsonify({"username": username, "logs": clean_logs}), 200
     #   else:
    #         return jsonify({"error_message": "Failed to retrieve log data."}), 500
       # else:
        #    return jsonify({"error_message": "Failed to retrieve job information."}), 500



@app.route('/logs-azure', methods=['GET', 'POST'])
def logs_azure():
    if current_user.is_authenticated:
        username = current_user.username
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job-id')

        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}

        response = requests.get(job_url, headers=headers)

        for job in response.json():
#    if isinstance(job, dict) and 'id' in job:

            

            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'

            log_response = requests.get(log_url, headers=headers)

            log_data = log_response.text

# with open('job_logs.txt', 'w') as log_file:

        # log_file.write(log_data + '\n')

        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

        

        # Remove ANSI escape codes

        clean_logs = ansi_escape.sub('', log_data)


        return render_template('logs-azure.html', username=username, logs=clean_logs)
    else:
        return redirect(url_for('login'))

@app.route('/json-logs-azure', methods=['GET', 'POST'])
def json_logs_azure():
        form = request.get_json()
        username = form['username']
        job_id = form['job_id']
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}

        response = requests.get(job_url, headers=headers)

 #       if response.status_code == 200:
            # Assuming response.json() returns a dictionary
        job_info = response.json()
        log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
        log_response = requests.get(log_url, headers=headers)

  #      if log_response.status_code == 200:
        log_data = log_response.text
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        clean_logs = ansi_escape.sub('', log_data)

                # Return a JSON response with job_id included
        return jsonify({"username": username, "job_id": job_id, "logs": clean_logs}),200


@app.route('/logs-gcp', methods=['GET', 'POST'])
def logs_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        # job_id = request.form.get('job-id')
        job_id = request.args.get('job-id')

        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}

        response = requests.get(job_url, headers=headers)

        for job in response.json():
#    if isinstance(job, dict) and 'id' in job:

            

            log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'

            log_response = requests.get(log_url, headers=headers)

            log_data = log_response.text

# with open('job_logs.txt', 'w') as log_file:

        # log_file.write(log_data + '\n')

        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

        

        # Remove ANSI escape codes

        clean_logs = ansi_escape.sub('', log_data)


        return render_template('logs-gcp.html', username=username, logs=clean_logs)
    else:
        return redirect(url_for('login'))

@app.route('/json-logs-gcp', methods=[ 'POST'])
def json_logs_gcp():
        form = request.get_json()
        username = form['username']
        job_id = form['job_id']
        access_token = 'glpat-LryS1Hu_2ZX17MSGhgkz'
        job_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}'
        headers = {'PRIVATE-TOKEN': access_token}

        response = requests.get(job_url, headers=headers)

#        if response.status_code == 200:
            # Assuming response.json() returns a dictionary
        job_info = response.json()

        log_url = f'https://gitlab.com/api/v4/projects/51819357/jobs/{job_id}/trace'
        log_response = requests.get(log_url, headers=headers)

#            if log_response.status_code == 200:
        log_data = log_response.text

        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        clean_logs = ansi_escape.sub('', log_data)
              # Return a JSON response with job_id included
        return jsonify({"username": username, "job_id": job_id, "logs": clean_logs})


@app.route('/creation-status-azure', methods=['GET', 'POST'])
def creation_status_azure():
    if current_user.is_authenticated:
        username = current_user.username
        job_name = 'azure_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()

        return render_template('cluster-details-azure.html', username=username, job_ids=job_ids)
    else:
        return redirect(url_for('login'))

@app.route('/json-creation-status-azure', methods=['POST'])
def json_creation_status_azure():
        form = request.get_json()
        username = form['username']
        job_name = 'azure_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()

        return jsonify({"username": username, "job_ids": job_ids}), 200



@app.route('/creation-status-gcp', methods=['GET', 'POST'])
def creation_status_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        job_name = 'gcp_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'azure_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()

        return render_template('cluster-details-gcp.html', username=username, job_ids=job_ids)
    else:
        return redirect(url_for('login'))



@app.route('/json-creation-status-gcp', methods=['POST'])
def json_creation_status_gcp():
        form = request.get_json()
        username = form['username']
        job_name = 'gcp_infrastructure'

        db_config = {
            'host': '4.188.187.102',
            'port': 3306,
            'user': 'root',
            'password': 'cockpitpro',
            'database': 'jobinfo'
        }

        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Fetch job IDs for username 'jini' and job_name 'gcp_infrastructure'
        query = f"SELECT job_id FROM users WHERE username = '{username}' AND job_name = '{job_name}'"
        cursor.execute(query)
        job_ids = [result[0] for result in cursor.fetchall()]

        # Close the database connection
        cursor.close()
        connection.close()

        return jsonify({"username": username, "job_ids": job_ids})


@app.route('/cloud')
def cloud():
    return render_template('cloud.html')


@app.route('/cloud_del')
def cloud_del():
    return render_template('cloud_del.html')


@app.route('/aws_del')
def aws_del():
    return render_template('aws_del.html')


@app.route('/az_del')
def az_del():
    return render_template('az_del.html')


@app.route('/gcp_del')
def gcp_del():
    return render_template('gcp_del.html')

 
@app.route('/aws')
@login_required
def aws():
    return render_template('aws.html')
@app.route('/aws1')
def aws1():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'aws')
        return render_template('aws1.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))
@app.route('/aws2')
def aws2():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'aws')
        return render_template('aws2.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))
@app.route('/delete_aws_credential', methods=['POST'])
def delete_aws_credential():
    Account_name = request.form.get('account_name')
    key_vault_name = Account_name+"aws"
    resource_group = "Cockpit"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
    delete_account(Account_name,'aws')
    return render_template('final-dashboard.html')
@app.route('/json_delete_aws_credential', methods=['POST'])
def json_delete_aws_credential():
    try:
        form = request.get_json()
        account_name = form['account_name']
        key_vault_name = account_name+"aws"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Invaild username."}
            return jsonify(error_msg), 404
        delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', 'Cockpit', key_vault_name)
        delete_account(account_name,'aws')
        return json.dumps( {
                "message": 'Credential delete successfully',
                "statusCode": 200
        })
    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "Invaild username"}
        return jsonify(error_msg), 404

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/json_update_aws_credential', methods=['POST'])
def json_update_aws_credential():
    try:
        form = request.get_json()
        Access_key = form['access_key']
        secret_Access_key = form['secret_access_key']
        User_name = form['user_name']
        account_name = form['account_name']
        key_vault_name = account_name+"aws"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "First Add Credential."}
            return jsonify(error_msg), 404
        update_keyvault_secret(vault_url, "Access-key", Access_key)
        update_keyvault_secret(vault_url, "secret-Access-key", secret_Access_key)
        return json.dumps( {
                "message": 'Credential Update successfully',
                "statusCode": 200
        })
    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "First add Credential"}
        return jsonify(error_msg), 404

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/update_aws_credential', methods=['POST'])
def update_aws_credential():
    Access_key = request.form.get('Access_key')
    secret_Access_key = request.form.get('secret_Access_key')
    User_name = request.form.get('User_name')
    account_name = request.form.get('account_name')
    key_vault_name = account_name+"aws"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "Access-key", Access_key)
    update_keyvault_secret(vault_url, "secret-Access-key", secret_Access_key)
 
    return render_template('final-dashboard.html')
@app.route('/json_submit_form_aws', methods=['POST'])
def json_submit_form_aws():
    form = request.get_json()
    Access_key = form['access_key']
    secret_Access_key = form['secret_access_key']
    User_name = form['User_name']
    account_name = form['account_name']

    resource_group_name = "Cockpit"  
    key_vault_name = account_name+"aws"
    location = "eastus"  # Choose a valid Azure location without special characters
    created = create_key_vault(key_vault_name,location,resource_group_name)
    new_username_record = UsernameTableaws(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    if not created:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "these credentials already exist"}
            return jsonify(error_msg), 200
    key_vault = f"https://{key_vault_name}.vault.azure.net/"
    store_secrets(key_vault,"Access-key", Access_key)
    store_secrets(key_vault,"secret-Access-key", secret_Access_key)
    store_secrets(key_vault,"username", User_name)
    store_secrets(key_vault,"account-name", account_name)
    new_user = UserAccount(username=User_name, account_name=account_name, cloud_name='aws')
    db.session.add(new_user)
    db.session.commit()
   
    return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
    })

@app.route('/submit_form', methods=['POST'])
def submit_form_aws():
    # Get  azure form data
    Access_key = request.form.get('Access_key')
    secret_Access_key = request.form.get('secret_Access_key')
    account_name = request.form.get('account_name')
    User_name = request.form.get('User_name')
    resource_group_name = "Cockpit"  
    key_vault_name = account_name+"aws"
    new_user = UserAccount(username=User_name, account_name=account_name, cloud_name='aws')
    db.session.add(new_user)
    db.session.commit()
    new_username_record = UsernameTableaws(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    location = "eastus"  # Choose a valid Azure location without special characters
    create_key_vault(key_vault_name,location,resource_group_name)
    key_vault = f"https://{key_vault_name}.vault.azure.net/"
    store_secrets(key_vault,"Access-key", Access_key)
    store_secrets(key_vault,"secret-Access-key", secret_Access_key)
    store_secrets(key_vault,"username", User_name)
    store_secrets(key_vault,"account-name", account_name)

    return render_template('create_aws.html')


@app.route('/aws_form', methods=['GET'])
def aws_form():
    return render_template('create_aws.html')
 
@app.route('/create_aws_form', methods=['GET'])
def create_aws_form():
    return render_template('create_aws.html')
 
@app.route('/success', methods=['GET'])
def success_aws():
    return render_template('success.html')

@app.route('/delete_aks', methods=['POST'])
def delete_aks():
    account_name =  request.form.get("account_name")
    aks_name = request.form.get('aks_name')
    resource_group = request.form.get('resource_group')
    new_username_record = UsernameTable(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
    gl.auth()
    project = gl.projects.get(project_id)
    with open('file.txt', 'w') as f:
        f.write(f'aks_name = "{aks_name}"\n')
        f.write(f'resource_group = "{resource_group}"\n')
        
    try:
        f = project.files.get(file_path='azure-delete/file.txt', ref=branch_name)
    except gitlab.exceptions.GitlabGetError:
        print("Error: Unable to retrieve file.")
        exit()
    file_content = base64.b64decode(f.content).decode("utf-8")
    file_path = f'azure-delete/file.txt'
    tf_config = f''' 
    aks_name = "{aks_name}"
    resourse_group = "{resource_group}"
    '''
    print(tf_config)
    file_content_normalized = file_content.strip().replace('\r\n', '\n')
    tf_config_normalized = tf_config.strip().replace('\r\n', '\n')
    print(tf_config_normalized)
    print(file_content_normalized)
    if file_content_normalized == tf_config_normalized:
        print("same contant")
        return render_template('az_del.html')
    else:
        print("Uploading tf file to gitlab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        file_name = "./user_name.json"
 
        with open(file_name, 'r') as file:
            user_data = json.load(file)
        check_and_delete_aks(username=account_name,resource_group=resource_group,aks_name=aks_name)
        return render_template('success.html')
def check_and_delete_aks(username, resource_group, aks_name):
    while True:
        aks_status = get_aks_cluster_status(aks_name, resource_group)
        if aks_status:
            cluster_info = aks_cluster.query.filter_by(aks_name=aks_name, resource_group=resource_group).one_or_none()
            if cluster_info:             # If the row exists, delete it            
              db.session.delete(cluster_info)             
              db.session.commit()
              break
        time.sleep(60)
        
def get_aks_cluster_status(aks_name, resource_group):
    # Use DefaultAzureCredential to authenticate with Azure
    credential = DefaultAzureCredential()
 
    # Create a ContainerServiceClient to interact with AKS
    client = ContainerServiceClient(credential, "f1aed9cb-fcad-472f-b14a-b1a0223fa5a5")
 
    # Get AKS cluster details
    cluster = client.managed_clusters.get(resource_group, aks_name)
 
    # Get the AKS cluster provisioning sta
    provisioning_state = cluster.provisioning_state.lower()
 
    if provisioning_state == "deleting":
        print("----------")
        return True
 
    else:
        print("not delete")
        return False  # You can handle other states as needed


@app.route('/json_delete_aks', methods=['POST'])
def json_delete_aks():
    try:
        form = request.get_json()
        account_name = form['account_name']
        aks_name = form['aks_name']
        resource_group = form['resource_group']
        new_username_record = UsernameTable(username=account_name)
        db.session.add(new_username_record)
        db.session.commit()
        file_path = 'azure-delete/file.txt'
        tf_config = f''' 
        aks_name = "{aks_name}"
        resource_group = "{resource_group}"
        '''
 
        print("Configuration:", tf_config)
        print("Uploading tf file to GitLab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        
        check_and_delete_aks(username=account_name, resource_group=resource_group, aks_name=aks_name)
        response_data = {'status': 'success', 'message': 'Cluster Deleted'}
        return jsonify(response_data), 200
 
    except Exception as e:
        # For other exceptions, you might want to log the full exception details
        response_data = {'status': 'error', 'message': str(e)}
        return jsonify(response_data), 404



@app.route('/delete_gke', methods=['POST'])
def delete_gke():
    gke_name = request.form.get('gke_name')
    account_name = request.form.get('account_name')
    region = request.form.get('region')
    projecct_id = request.form.get('project_id')
    new_username_record = UsernameTablegcp(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
    gl.auth()
    project = gl.projects.get(project_id)
    with open('file.txt', 'w') as f:
        f.write(f'gke-name = "{gke_name}"\n')
        f.write(f'region = "{region}"\n')
        f.write(f'project_id = "{projecct_id}"\n')
    try:
        f = project.files.get(file_path='gke-delete/file.txt', ref=branch_name)
    except gitlab.exceptions.GitlabGetError:
        print("Error: Unable to retrieve file.")
        exit()
    file_content = base64.b64decode(f.content).decode("utf-8")
    file_path = f'gke-delete/file.txt'
    tf_config = f''' 
    gke_name = "{gke_name}"
    region = "{region}"
    project_id = "{projecct_id}"
    '''
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    check_and_delete_gke_cluster_status(account_name,"us-central1-f",gke_name,project)
    return render_template('success.html')
def check_and_delete_gke_cluster_status(account_name,region,gke_name,project):
    while True:
        # Check the AKS cluster status (replace this with your actual implementation)
        eks_cluster_created = check_gke_cluster_deletion_status(account_name,gke_name,region,project)
 
        if not eks_cluster_created:
            # Store AKS cluster information in the database
            delete_gke(account_name,gke_name)
            break  # Break the loop once the AKS cluster is created
 
        # Add a sleep interval to avoid continuous checking and reduce resource usage
        time.sleep(60)
 
def check_gke_cluster_deletion_status(account_name,gke_name,region,project):
    key_vault_url_gcp = f"https://{account_name}gcp.vault.azure.net/"
    gcp_credentials_secret = "your-secret-name"  # Update with your actual secret name

    try:
        print(gke_name)
        print(region)
        print(project)
        # Retrieve credentials from Azure Key Vault
        credential_gcp = DefaultAzureCredential()
        secret_client_gcp = SecretClient(vault_url=key_vault_url_gcp, credential=credential_gcp)
        print("_____")
        # Retrieve the GCP credentials JSON from Key Vault
        gcp_credentials_json = secret_client_gcp.get_secret(gcp_credentials_secret).value
        print("gcp_credentials_json")
        # Parse the JSON string into a dictionary
        gcp_credentials_dict = json.loads(gcp_credentials_json)
        print(gcp_credentials_dict)
        # Use the parsed dictionary to create a service account credentials object
        gcp_credentials = service_account.Credentials.from_service_account_info(gcp_credentials_dict)

        # Use the service account credentials for the discovery build
        client = container_v1.ClusterManagerClient(credentials=gcp_credentials)

        # Define the parent (project) and cluster ID
        project_id = project  # Update with your GCP project ID
        cluster_id = gke_name  # Ensure this matches the actual cluster name
        location = region # Update if your cluster is in a different location
        print(gke_name)
        print(location)
        print(project_id)
        # Construct the cluster resource name
        cluster_path = f"projects/{project_id}/locations/{location}/clusters/{cluster_id}"

        # Attempt to get information about the cluster
        cluster = client.get_cluster(name=cluster_path)

        if cluster:
            print("The GKE cluster exists.")
            return True
        
    except Exception as e:
        # Print the error message if an exception occurs
        print("An error occurred:", e)
        print("The GKE cluster does not exist or there was an error.")
        return False
def delete_gke(account_name,gke_name):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = "DELETE FROM gke_cluster WHERE username = %s and eks_name = %s"
        
        # Execute the query with the provided parameter
        cursor.execute(query, (account_name,gke_name,))

        # Commit the changes to the database
        connection.commit()
        return

@app.route('/json_delete_gke', methods=['POST'])
def json_delete_gke():
  try:
    form = request.get_json()
    account_name = form['account_name']
    gke_name = form['gke_name']
    region = form['region']
    project = form['project_id']
    new_username_record = UsernameTablegcp(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    with open('file.txt', 'w') as f:
        f.write(f'gke-name = "{gke_name}"\n')
        f.write(f'region = "{region}"\n')
        f.write(f'project_id = "{project_id}"\n')
    region = region + "-f"
    file_path = f'gke-delete/file.txt'
    tf_config = f''' 
    gke_name = "{gke_name}"
    region = "{region}"
    project_id = "{project}"
    '''
    print("Configuration:", tf_config)
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    print("Tf File uploaded successfully")
    check_and_delete_gke_cluster_status(account_name,"us-central1-f",gke_name,project)
    response_data = {'status': 'success', 'message': 'Cluster is deleted'}
    return jsonify(response_data),202

  except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        response_data = {'status': 'error', 'message': error_message}
        return jsonify(response_data),404




@app.route('/delete_eks', methods=['POST'])
def delete_eks():
    account_name = request.form.get('account_name')
    eks_name = request.form.get('eks_name')
    Region = request.form.get('Region')
    Node = request.form.get('ng_name')
    gl = gitlab.Gitlab(gitlab_url, private_token=access_token)
    gl.auth()

    project = gl.projects.get(project_id)
    with open('file.txt', 'w') as f:
        f.write(f'eks-name = "{eks_name}"\n')
        f.write(f'region = "{Region}"\n')
        f.write(f'node = "{Node}"\n')
    try:
        f = project.files.get(file_path='aws-delete/file.txt', ref=branch_name)
    except gitlab.exceptions.GitlabGetError:
        print("Error: Unable to retrieve file.")
        exit()
    file_content = base64.b64decode(f.content).decode("utf-8")
    file_path = f'aws-delete/file.txt'
    tf_config = f''' 
    eks_name = "{eks_name}"
    region = "{Region}"
    node = "{Node}"
    '''

    file_content_normalized = file_content.strip().replace('\r\n', '\n')
    tf_config_normalized = tf_config.strip().replace('\r\n', '\n')
    
    print("Uploading tf file to gitlab")
    key_vault = account_name + "aws"

    new_username_record = UsernameTableaws(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    check_and_delete_eks('us-east-1',eks_name,key_vault)
    print("Tf File uploaded successfully")
    return render_template('success.html')
def delete_eks(account_name,cloud):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = "DELETE FROM user_account WHERE account_name = %s and cloud_name = %s"
        
        # Execute the query with the provided parameter
        cursor.execute(query, (account_name,cloud,))

        # Commit the changes to the database
        connection.commit()
        return
def check_and_delete_eks(region, eks_name, key_vault):
    
    while True:
        print("not")
        key_vault_url = f"https://{key_vault}.vault.azure.net/"
        eks_status = get_eks_cluster_status_with_keyvault(eks_name, region, 'Access-key','secret-Access-key',key_vault_url)
        if not eks_status:
            cluster_info = eks_cluster.query.filter_by(eks_name=eks_name, region="us-east-1").one_or_none()
            if cluster_info:   
              print("yes")          # If the row exists, delete it            
              db.session.delete(cluster_info)             
              db.session.commit()
              break
        print("time")
        time.sleep(360)
        
def get_eks_cluster_status_with_keyvault(eks_name, region, access_key_secret, secret_access_key_secret,key_vault_url):
    try:
        # Retrieve credentials from Azure Key Vault
        credential_aws = DefaultAzureCredential()
        secret_client_aws = SecretClient(vault_url=key_vault_url, credential=credential_aws)

        # Retrieve the secrets from Key Vault
        aws_access_key = secret_client_aws.get_secret(access_key_secret).value
        aws_secret_access_key = secret_client_aws.get_secret(secret_access_key_secret).value

        # Initialize the Boto3 EKS client with retrieved AWS credentials
        eks_client = boto3.client('eks', region_name=region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_access_key)

        # Describe the EKS cluster
        response = eks_client.describe_cluster(name=eks_name)

        # Get the EKS cluster status
        cluster_status = response['cluster']['status'].lower()

        if cluster_status == "deleting":
            print("EKS cluster is in 'deleting' state.")
            return True
        else:
            print("EKS cluster is not in 'deleting' state.")
            return False  # You can handle other states as needed

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "ResourceNotFoundException":
            # If the cluster is not found, return False
            return False
        else:
            # Handle other exceptions if needed
            print(f"Error: {e}")
            return False
 # You can handle other states as needed
@app.route('/json_delete_eks', methods=['POST'])
def json_delete_eks():
    try:
        form = request.get_json()
        account_name = form['account_name']
        eks_name = form['eks_name']
        region = form['region']
        node = form['node']

        with open('file.txt', 'w') as f:
            f.write(f'eks-name = "{eks_name}"\n')
            f.write(f'region = "{region}"\n')
            f.write(f'node = "{node}"\n')

        file_path = 'aws-delete/file.txt'
        tf_config = f''' 
        eks_name = "{eks_name}"
        region = "{region}"
        node = "{node}"
        '''

        print("Configuration:", tf_config)
        print("Uploading tf file to gitlab")
        key_vault = account_name + "aws"

        new_username_record = UsernameTableaws(username=account_name)
        db.session.add(new_username_record)
        db.session.commit()
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        check_and_delete_eks('us-east-1',eks_name,key_vault)
        print("Tf File uploaded successfully")
      

        # Return JSON response
        response_data = {'status': 'success', 'message': 'Delete request triggered the pipeline please wait sometime...'}
        return jsonify(response_data),202

    except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        response_data = {'status': 'error', 'message': error_message}
        return jsonify(response_data),404

@app.route('/json_create_aws', methods=['POST'])
def json_create_aws():
   
        form = request.get_json()
        account_name = form['account_name']
        eks_name = form['eks_name']
        Region = form['region']
        instance_type = form['instance_type']
        eks_version = form['eks_version']
        desired_size = form['desired_size']
        max_size = form['max_size']
        min_size = form['min_size']
        cluster_type = form['cluster_type']
        eks_version = float(eks_version)
    
        # Create the content for terraform.tfvars
        with open('terraform.tfvars', 'w') as f:
            f.write(f'eks_name = "{eks_name}"\n')
            f.write(f'Region = "{Region}"\n')
            f.write(f'instance_type = "{instance_type}"\n')
            f.write(f'eks_version = "{eks_version}"\n')
            f.write(f'desired_size = "{desired_size}"\n')
            f.write(f'max_size = "{max_size}"\n')
            f.write(f'min_size = "{min_size}"\n')
            f.write(f'cluster_type = "{cluster_type}"\n')

        # file_name = "./user_name.json"

        # with open(file_name, 'r') as file:
        #     user_data = json.load(file)
        key_vault = account_name+"aws"
        file_name = f'terraform-{account_name}.tfvars'
        file_path = f'aws/templates/{file_name}'
        new_username_record = UsernameTableaws(username=account_name)
        db.session.add(new_username_record)
        db.session.commit()
        tf_config = f'''
    cluster_name = "{eks_name}"
    region = "{Region}"
    instance_type = "{instance_type}"
    eks_version = "{eks_version}"
    desired_size = "{desired_size}"
    max_size = "{max_size}"
    min_size = "{min_size}"
    cluster_type = "{cluster_type}"
    '''
        print("Configuration:", tf_config)

        print("Configuration:", tf_config)

        
        print("Uploading tf file to gitlab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        check_and_store_eks_cluster_status(account_name, eks_name, 'us-east-1',key_vault)

        # You can also redirect the user to a success page if needed
        return json.dumps({
            "message": "Cluster created",
            "statusCode": 200
        })


@app.route('/create_aws', methods=['POST'])
def create_aws():
    if current_user.is_authenticated:
        username = current_user.username
    # Retrieve form data
        account_name = request.form.get('account_name')
        eks_name = request.form.get('eks_name')
        Region = request.form.get('Region')
        instance_type = request.form.get('instance_type')
        eks_version = request.form.get('eks_version')
        desired_size = request.form.get('desired_size')
        max_size = request.form.get('max_size')
        min_size = request.form.get('min_size')
        cluster_type = request.form.get('cluster_type')
        
        eks_version = str(eks_version)
        eks_version = version.parse(eks_version)
    
        # Create the content for terraform.tfvars
        with open('terraform.tfvars', 'w') as f:
            f.write(f'eks_name = "{eks_name}"\n')
            f.write(f'Region = "{Region}"\n')
            f.write(f'instance_type = "{instance_type}"\n')
            f.write(f'eks_version = "{eks_version}"\n')
            f.write(f'desired_size = "{desired_size}"\n')
            f.write(f'max_size = "{max_size}"\n')
            f.write(f'min_size = "{min_size}"\n')
            f.write(f'cluster_type = "{cluster_type}"\n')

        # file_name = "./user_name.json"

        # with open(file_name, 'r') as file:
        #     user_data = json.load(file)
    
        # user = Data(username=user_data["user"], cloudname='aws', clustername=eks_name)
        # db.session.add(user)
        # db.session.commit()
        key_vault = account_name+"aws"
        file_name = f'terraform-{account_name}.tfvars'
        file_path = f'aws/templates/{file_name}'
        new_username_record = UsernameTableaws(username=account_name)
        db.session.add(new_username_record)
        db.session.commit()
        tf_config = f'''
    cluster_name = "{eks_name}"
    region = "{Region}"
    instance_type = "{instance_type}"
    eks_version = "{eks_version}"
    desired_size = "{desired_size}"
    max_size = "{max_size}"
    min_size = "{min_size}"
    cluster_type = "{cluster_type}"
    '''
        print("Configuration:", tf_config)

        # print("Configuration:", tf_config)

        
        print("Uploading tf file to gitlab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        check_and_store_eks_cluster_status(account_name, eks_name, 'us-east-1',key_vault)
        # You can also redirect the user to a success page if needed
        session['info'] = 'Some information'

        return redirect(url_for('jobs_aws'))
def check_and_store_eks_cluster_status(account, eks_name, Region,key_vault):
    while True:
        # Check the AKS cluster status (replace this with your actual implementation)
        aks_cluster_created = check_eks_cluster(eks_name,'us-east-1',key_vault)
 
        if aks_cluster_created:
            # Store AKS cluster information in the database
            store_eks_cluster_info(account, 'aws', 'us-east-1', eks_name)
            break  # Break the loop once the AKS cluster is created
 
        # Add a sleep interval to avoid continuous checking and reduce resource usage
        time.sleep(120)
 
def check_eks_cluster(eks_name, region,key_vault):
    try:

        key_vault_url_aws = f"https://{key_vault}.vault.azure.net/"
        access_key_secret = "Access-key"
        secret_access_key_secret = "secret-Access-key"

        # Retrieve credentials from Azure Key Vault
        credential_aws = DefaultAzureCredential()
        secret_client_aws = SecretClient(vault_url=key_vault_url_aws, credential=credential_aws)

        # Retrieve the secrets from Key Vault
        aws_access_key = secret_client_aws.get_secret(access_key_secret).value
        aws_secret_access_key = secret_client_aws.get_secret(secret_access_key_secret).value

        # Initialize the Boto3 EKS client with retrieved AWS credentials
        eks_client = boto3.client('eks', region_name=region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_access_key)

        # Describe the EKS cluster
        response = eks_client.describe_cluster(name=eks_name)

        # If the cluster is found, return True
        return True

    

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "ResourceNotFoundException":
            # If the cluster is not found, return False
            return False
        else:
            # Handle other exceptions if needed
            print(f"Error: {e}")
            return False
 
def store_eks_cluster_info(account, cloudname,region, eks_name):
    cluster_info = eks_cluster(
        username=account,
        cloudname=cloudname,
        region=region,
        eks_name=eks_name
    )
    db.session.add(cluster_info)
    db.session.commit()
#azure form
@app.route('/azure')
def azure():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'azure')
        return render_template('azure.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))
@app.route('/azure_account')
def azure_account():
    return render_template('azure_account.html')
@app.route('/already', methods=['POST'])
def already():
    username = request.form.get('User_name')
    name = get_account(username,'azure')
        
    return render_template('azure.html', name=name)
@app.route('/azureuser_insert', methods=['POST'])
def azureuser_insert():
    try:
        username = request.form.get('User_name')
        account_name = request.form.get('account_name')
        new_user = UserAccount(username=username, account_name=account_name, cloud_name='azure')
        db.session.add(new_user)
        db.session.commit()
        name = get_account(username,'azure')
        
        return render_template('azure.html', name=name)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_account(username,cloud_name):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
    
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = f"SELECT distinct account_name FROM user_account WHERE username = '{username}' and cloud_name = '{cloud_name}'"
        cursor.execute(query)
        name = [result[0] for result in cursor.fetchall()]
        cursor.close()
        connection.close()
        return name
def delete_account(account_name,cloud):
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = "DELETE FROM user_account WHERE account_name = %s and cloud_name = %s"
        
        # Execute the query with the provided parameter
        cursor.execute(query, (account_name,cloud,))

        # Commit the changes to the database
        connection.commit()
        return
@app.route('/json_get_account', methods=['POST'])
def json_get_account():
        form = request.get_json()
        username = form['User_name']
        cloud_name = form['cloud_name']
        db_config = {
        'host': '4.188.187.102',
        'port': 3306,
        'user': 'root',
        'password': 'cockpitpro',
        'database': 'jobinfo'
        }
    
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        query = f"SELECT distinct account_name FROM user_account WHERE username = '{username}' and cloud_name = '{cloud_name}'"
        cursor.execute(query)
        name = [result[0] for result in cursor.fetchall()]
        cursor.close()
        connection.close()
        if not name:
            # Handle the case when there are no clusters
              return jsonify({"username": username,"cloud_name": cloud_name, "account_name": [], "message": "No account name available."}), 200

        return jsonify({"username": username,"cloud_name": cloud_name, "account_name": name}),200
@app.route('/azure1')
def azure1():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'azure')
        return render_template('azure1.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))

@app.route('/azure2')
def azure2():
    if current_user.is_authenticated:
        username = current_user.username
        accounts = get_account(username,'azure')
        return render_template('azure2.html', username=username,accounts=accounts)
        
    else:
        return redirect(url_for('login'))
@app.route('/delete_azure_credential', methods=['POST'])
def delete_azure_credential():
    Account_name = request.form.get('account_name')
    key_vault_name = Account_name+"azure"
    resource_group = "Cockpit"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
    delete_account(Account_name,'azure')
    return render_template('final-dashboard.html')
@app.route('/json_delete_azure_credential', methods=['POST'])
def json_delete_azure_credential():
    try:
        form = request.get_json()
        Account_name = form['account_name']
        key_vault_name = Account_name + "azure"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        resource_group = "Cockpit"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            error_msg = {"error message": "Invaild Account name."}
            return jsonify(error_msg), 404
        
        delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
        delete_account(Account_name,'azure')
        return json.dumps({
            "message": 'Credential delete successfully',
            "statusCode": 200
        })

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"error message": "Invaild Account name."}
        return jsonify(error_msg), 404

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
def delete_keyvault(vault_url, subscription_id, resource_group, keyvault_name):
    # Initialize the Key Vault client
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=vault_url, credential=credential)
    client = KeyVaultManagementClient(credential, subscription_id)
    client.vaults.delete(resource_group, keyvault_name)

@app.route('/update_azure_credential', methods=['POST'])
def update_azure_credential():
    subscription_id = request.form.get('subscription_id')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    tenant_id = request.form.get('tenant_id')
    User_name = request.form.get('User_name')
    account_name = request.form.get('account_name')
    key_vault_name = account_name+"azure"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "client-id", client_id)
    update_keyvault_secret(vault_url, "client-secret", client_secret)
    update_keyvault_secret(vault_url, "tenant-id", tenant_id)
    update_keyvault_secret(vault_url, "subscription-id", subscription_id)
    return render_template('final-dashboard.html')

def update_keyvault_secret(vault_url, secret_name, new_secret_value):
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url=vault_url, credential=credential)
    existing_secret = secret_client.get_secret(secret_name)
    updated_secret = secret_client.set_secret(secret_name, new_secret_value)
    print(f"Secret '{secret_name}' updated successfully.")
    print(f"Old Secret Value: {existing_secret.value}")
    print(f"New Secret Value: {updated_secret.value}")
def create_key_vault(key_vault_name,location,rg):
    key_vault_name = key_vault_name
    key_vault_name = key_vault_name.replace("_", "-")
    location = location  # Choose a valid Azure location without special characters
    rg = rg
    try:
        # Use Azure CLI to get the access token
        access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
        exit(1)

    try:
        subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", rg, "--location", location])
        print(f"Azure Key Vault '{key_vault_name}' created successfully.")
        return True
    except subprocess.CalledProcessError:
        print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation.")
        return False
def store_secrets(key_vault_url, secret_name, secret_value):
    credential = DefaultAzureCredential()

    # Create a SecretClient to interact with the Key Vault
    secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

    try:
        # Create or update the secret in the Key Vault
        secret = secret_client.set_secret(secret_name, secret_value)
        print(f"Secret '{secret.name}' created or updated successfully.")
    except Exception as e:
        print(f"Error: {e}")
@app.route('/submit_form_azure', methods=['POST'])
def submit_form_azure():
    # Get  azure form data
    subscription_id = request.form.get('subscription_id')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    tenant_id = request.form.get('tenant_id')
    account_name = request.form.get('account_name')
    User_name = request.form.get('User_name')
    resource_group_name = "Cockpit"  
    key_vault_name = account_name+"azure"
    new_user = UserAccount(username=User_name, account_name=account_name, cloud_name='azure')
    db.session.add(new_user)
    db.session.commit()
    location = "eastus"  # Choose a valid Azure location without special characters
    create_key_vault(key_vault_name,location,resource_group_name)
    key_vault = f"https://{key_vault_name}.vault.azure.net/"
    store_secrets(key_vault,"client-id", client_id)
    store_secrets(key_vault,"client-secret", client_secret)
    store_secrets(key_vault,"subscription-id", subscription_id)
    store_secrets(key_vault,"tenant-id", tenant_id)
    store_secrets(key_vault,"username", User_name)
    store_secrets(key_vault,"account-name", account_name)

    return render_template('create_aks.html')


@app.route('/json_update_azure_credential', methods=['POST'])
def json_update_azure_credential():
    try:
        form = request.get_json()
        subscription_id = form['subscription_id']
        client_id = form['client_id']
        client_secret = form['client_secret']
        tenant_id = form['tenant_id']
        User_name = form['User_name']
        account_name = form['account_name']
        key_vault_name = account_name + "azure"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "First Add Credential."}
            return jsonify(error_msg), 404
        
        update_keyvault_secret(vault_url, "client-id", client_id)
        update_keyvault_secret(vault_url, "client-secret", client_secret)
        update_keyvault_secret(vault_url, "tenant-id", tenant_id)
        update_keyvault_secret(vault_url, "subscription-id", subscription_id)
        
        return json.dumps({
            "message": 'Credential Update successfully',
            "statusCode": 200
        })

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "First add Credential"}
        return jsonify(error_msg), 404

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500

@app.route('/json_submit_form_azure', methods=['POST'])
def json_submit_form_azure():
    # Get  azure form data
    form = request.get_json()
    subscription_id = form['subscription_id']
    client_id = form['client_id']
    client_secret = form['client_secret']
    tenant_id = form['tenant_id']
    User_name = form['User_name']
    account_name = form['account_name']

    resource_group_name = "Cockpit"  
    key_vault_name = account_name+"azure"
    location = "eastus"  # Choose a valid Azure location without special characters
    created = create_key_vault(key_vault_name,location,resource_group_name)
    new_username_record = UsernameTable(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    if not created:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "these credentials already exist"}
            return jsonify(error_msg), 200
    key_vault = f"https://{key_vault_name}.vault.azure.net/"
    store_secrets(key_vault,"client-id", client_id)
    store_secrets(key_vault,"client-secret", client_secret)
    store_secrets(key_vault,"subscription-id", subscription_id)
    store_secrets(key_vault,"tenant-id", tenant_id)
    store_secrets(key_vault,"username", User_name)
    store_secrets(key_vault,"account-name", account_name)
    new_user = UserAccount(username=User_name, account_name=account_name, cloud_name='azure')
    db.session.add(new_user)
    db.session.commit()
   
    return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
    })
   # flash('Credential Succesfully added.', 'success')

@app.route('/create_aks',methods=['GET'])
def get_create_aks():
    return render_template('create_aks.html')
 
 
@app.route('/azure_form', methods=['GET'])
def azure_form():
    return render_template('create_aks.html')
 
@app.route('/create_aks_form', methods=['GET'])
def create_aks_form():
    return render_template('create_aks.html')
 
@app.route('/success', methods=['GET'])
def success_aks():
    return render_template('success.html')
 
@app.route('/create_aks', methods=['POST'])
def create_aks():
    # Retrieve form data
    resource_group = request.form.get('resource_group')
    Region = request.form.get('Region')
    availability_zones = request.form.getlist('availability_zones[]')  # Use getlist to get multiple selected values
    aks_name = request.form.get('aks_name')
    aks_version = request.form.get('aks_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')
    account_name = request.form.get('account_name')
    new_username_record = UsernameTable(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    file_name = "./user_name.json"
 
    with open(file_name, 'r') as file:
        user_data = json.load(file)
 
        
 
    user_data["rg_name"] = resource_group
    user_data["Region"] = Region
    user_data["availability_zones"] = availability_zones
    user_data["aks_name"] = aks_name
    user_data["aks_version"] = aks_version
    user_data["node_count"] = node_count
    user_data["cluster_type"] = cluster_type
    user_data["account_name"] = account_name
 
 
    print("user name is:", user_data["user"])
    user = Data(username=account_name, cloudname='azure', clustername=user_data["aks_name"])
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["account_name"]}.tfvars'
    
 
    
    aks_version = version.parse(aks_version)
    
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None
 
    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')
 
    # Convert availability_zones to a string containing an array
    availability_zones_str = '[' + ', '.join(['"' + zone + '"' for zone in availability_zones]) + ']'
 
    with open(file_name, 'w') as f:
        f.write(f'resource_group = "{resource_group}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'availability_zones = {availability_zones_str}\n')
        f.write(f'aks_name = "{aks_name}"\n')
        f.write(f'aks_version = "{aks_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')
 
    file_path = f'templates/user-data/{file_name}'
    file_path = f'azure/template/{file_name}'
    if vm_name is not None:
        # Include vm_name and vm_pass if vm_name is not None
        tf_config = f'''
rg_name = "{resource_group}"
rg_location = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
private_cluster_enabled = "true"
vm_name = "{vm_name}"
vm_pass = "{vm_pass}"'''
    else:
        tf_config = f'''
rg_name = "{resource_group}"
rg_location = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
private_cluster_enabled = "false"'''   
    print("Configuration:", tf_config)
    
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
 
    session['info'] = 'Some information'
 
    # Continuously check and store AKS cluster status in the background
    check_and_store_aks_cluster_status(username=account_name,resource_group=resource_group,aks_name=aks_name,Region=Region)
 
    return redirect(url_for('jobs_azure'))
    # return render_template('success.html')
 
def check_and_store_aks_cluster_status(username, resource_group,aks_name, Region):
    while True:
        # Check the AKS cluster status (replace this with your actual implementation)
        aks_cluster_created = check_aks_cluster_creation_status(aks_name,resource_group)
 
        if aks_cluster_created:
            # Store AKS cluster information in the database
            store_aks_cluster_info(username, 'azure', resource_group, Region, aks_name)
            break  # Break the loop once the AKS cluster is created
 
        # Add a sleep interval to avoid continuous checking and reduce resource usage
        time.sleep(60)
 
def check_aks_cluster_creation_status(aks_name, resource_group):
    try:
        # Use the az CLI to get AKS cluster details
        cmd = f'az aks show --resource-group {resource_group} --name {aks_name}'
        subprocess.run(cmd, check=True, shell=True)
        
        # If the subprocess runs successfully, the cluster exists
        return True
    except subprocess.CalledProcessError:
        # If an error occurs, the cluster does not exist
        return False
 
def store_aks_cluster_info(username, cloudname, resource_group, region, aks_name):
    cluster_info = aks_cluster(
        username=username,
        cloudname=cloudname,
        resource_group=resource_group,
        region=region,
        aks_name=aks_name
    )
    db.session.add(cluster_info)
    db.session.commit()

 
@app.route('/json_create_aks', methods=['POST'])
def json_create_aks():
    # Retrieve form data
    form = request.get_json()
    resource_group = form['resource_group']
    Region = form['Region']
    availability_zones = form.get('availability_zones', [])  # Use getlist to get multiple selected values
    aks_name = form['aks_name']
    aks_version = form['aks_version']
    node_count = form['node_count']
    cluster_type = form['cluster_type']
    account_name = form['account_name']
    new_username_record = UsernameTable(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    file_name = "./user_name.json"

    try:
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                user_data = json.load(file)
        else:
            return json.dumps({
                "message": "Failed to trigger pipeline user already trigged the pipeline"
            }), 409  # Use 404 to indicate "Not Found" if the file is not found
    except FileNotFoundError:
        return json.dumps({
            "message": "Failed to trigger pipeline user already trigged the pipeline"
        }), 409
    except IOError as e:
        return json.dumps({
        "message": f"Failed to read the file: {str(e)}"
        }), 500 

    print("user name is:", user_data["user"])

    file_name = f'terraform-{account_name}.tfvars'
    file_path = f'azure/template/{file_name}'    

    aks_version = float(aks_version)
    
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None

    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')

    # Convert availability_zones to a string containing an array
    availability_zones_str = '[' + ', '.join(['"' + zone + '"' for zone in availability_zones]) + ']'

    with open(file_name, 'w') as f:
        f.write(f'resource_group = "{resource_group}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'availability_zones = {availability_zones_str}\n')
        f.write(f'aks_name = "{aks_name}"\n') 
        f.write(f'aks_version = "{aks_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    #file_path = f'templates/user-data/{file_name}'

    if vm_name is not None:
        # Include vm_name and vm_pass if vm_name is not None
        tf_config = f'''
rg_name = "{resource_group}"
region = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"
vm_name = "{vm_name}"
vm_pass = "{vm_pass}"'''
    else:
        tf_config = f'''
rg_name = "{resource_group}"
region = "{Region}"
availability_zones = "{availability_zones}"
aks_name = "{aks_name}"
aks_version = "{aks_version}"
node_count = "{node_count}"'''
   
    print("Configuration:", tf_config)

    
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    check_and_store_aks_cluster_status(username=account_name,resource_group=resource_group,aks_name=aks_name,Region=Region)

    os.remove(file_name)
    os.remove("user_name.json")
    return json.dumps( {
            "message": 'Creating AKS cluster. This may take some time. Please wait... ',
            "statusCode": 200
        })

@app.route('/gcp')
def gcp():
    return render_template('gcp.html')
@app.route('/gcp1')
def gcp1():
    return render_template('gcp1.html')
@app.route('/gcp2')
def gcp2():
    return render_template('gcp2.html')
@app.route('/json_update_credential_gcp', methods=['POST'])
def json_update_credential_gcp():
    if 'jsonFile' not in request.files:
        return jsonify({"message": 'No JSON file uploaded'}), 400

    json_file = request.files['jsonFile']

    # Check if the file has a filename
    if json_file.filename == '':
        return jsonify({"message": 'No filename provided for JSON file'}), 400

    # Check if the file is a JSON file
    if not json_file.filename.endswith('.json'):
        return jsonify({"message": 'Uploaded file is not a JSON file'}), 400

    # Read the file content and decode it
    file_content = json_file.read()
    secret_string = file_content.decode('utf-8')

    # Retrieve other form data
    form = request.form
    User_name = form.get('User_name')
    account_name = form.get('account_name')
    location = "eastus"  # Choose a valid Azure location without special characters
    resource_group_name = "Cockpit"  

    # Create key vault
    key_vault_name = account_name + "gcp"
    key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
    if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
        error_msg = {"message": "First Add Credential."}
        return jsonify(error_msg), 404
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "your-secret-name", secret_string)
    update_keyvault_secret(vault_url, "username", User_name)
    update_keyvault_secret(vault_url, "account-name", account_name)

    return jsonify({"message": 'Credentials update successfully', "statusCode": 200})


@app.route('/delete_credential_gcp', methods=['POST'])
def delete_credential_gcp():
    account_name = request.form.get('account_name')
    key_vault_name = account_name+"gcp"
    resource_group = "Cockpit"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
    delete_account(account_name,'gcp')
    return render_template('final-dashboard.html')
@app.route('/json_delete_credential_gcp', methods=['POST'])
def json_delete_credential_gcp():
    try:
        form = request.get_json()
        account_name = form['account_name']
        key_vault_name = account_name+"gcp"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Invaild username."}
            return jsonify(error_msg), 404
        delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', 'Cockpit', key_vault_name)
        delete_account(account_name,'gcp')
        return json.dumps( {
                "message": 'Credential delete successfully',
                "statusCode": 200
        })
    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "Invaild username"}
        return jsonify(error_msg), 404

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/update_credential_gcp', methods=['POST'])
def update_credential_gcp():  
    if 'jsonFile' not in request.files:
        return json.dumps( {
            "message": 'failed to create key-vault'
        }),409
    json_file = request.files['jsonFile'] # Check if the file has a filename
    if json_file.filename == '':
        return render_template('./file_submit.html') # Check if the file is a JSON file
    if not json_file.filename.endswith('.json'):
        return render_template('./submit.html')  
    file_content = json_file.read()
    User_name = request.form.get('User_name')
    account_name = request.form.get('account_name')
    key_vault_name = account_name+"gcp"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "your-secret-name", file_content)
    update_keyvault_secret(vault_url, "username", User_name)
    update_keyvault_secret(vault_url, "account-name", account_name)
    return render_template('final-dashboard.html')
@app.route('/submit_form_gke', methods=['POST'])
def submit_form_gke():
    # Retrieve form data
    account_name = request.form.get('account_name')
    project = request.form.get('project')
    Region = request.form.get('region')
    gke_name = request.form.get('gke_name')
    gke_version = request.form.get('gke_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')
    gke_version = str(gke_version)
    gke_version = version.parse(gke_version)
    new_username_record = UsernameTablegcp(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None
 
    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'project = "{project}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'gke_name = "{gke_name}"\n')
        f.write(f'gke_version = "{gke_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    # file_name = "./user_name.json"

    # with open(file_name, 'r') as file:
    #     user_data = json.load(file)
    # user = Data(username=user_data["user"], cloudname='gcp', clustername=gke_name)
    # db.session.add(user)
    # db.session.commit()
    file_name = f'terraform-{account_name}.tfvars'
    file_path = f'gcp/template/{file_name}'

    tf_config = f'''
    project = "{project}"
    Region = "{Region}"
    cluster_name = "{gke_name}"
    gke_version = "{gke_version}"
    node_count = "{node_count}"
    cluster_type = "{cluster_type}"
    vm_name = "{vm_name}"  
    vm_pass = "{vm_pass}" 
    '''




    # Print the tf_config (optional)
    print("Configuration:", tf_config)

    # Upload the tfvars file to GitLab
    print("Uploading tfvars file to GitLab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tfvars File uploaded successfully")
    # time.sleep(360)
    print("after 4 mins")
    check_and_store_gke_cluster_status(account_name,"us-central1-f",gke_name,project)
    # You can also redirect the user to a success page if needed
    
    return render_template('success.html')
def check_and_store_gke_cluster_status(account_name,region,gke_name,project):
    while True:
        # Check the AKS cluster status (replace this with your actual implementation)
        eks_cluster_created = check_gke_cluster_creation_status(account_name,gke_name,region,project)
 
        if eks_cluster_created:
            # Store AKS cluster information in the database
            store_gke_cluster_info(account_name, 'gcp', region, gke_name)
            break  # Break the loop once the AKS cluster is created
 
        # Add a sleep interval to avoid continuous checking and reduce resource usage
        time.sleep(60)
 
def check_gke_cluster_creation_status(account_name,gke_name,region,project):
    key_vault_url_gcp = f"https://{account_name}gcp.vault.azure.net/"
    gcp_credentials_secret = "your-secret-name"  # Update with your actual secret name

    try:
        print(gke_name)
        print(region)
        print(project)
        # Retrieve credentials from Azure Key Vault
        credential_gcp = DefaultAzureCredential()
        secret_client_gcp = SecretClient(vault_url=key_vault_url_gcp, credential=credential_gcp)
        print("_____")
        # Retrieve the GCP credentials JSON from Key Vault
        gcp_credentials_json = secret_client_gcp.get_secret(gcp_credentials_secret).value
        print("gcp_credentials_json")
        # Parse the JSON string into a dictionary
        gcp_credentials_dict = json.loads(gcp_credentials_json)
        print(gcp_credentials_dict)
        # Use the parsed dictionary to create a service account credentials object
        gcp_credentials = service_account.Credentials.from_service_account_info(gcp_credentials_dict)

        # Use the service account credentials for the discovery build
        client = container_v1.ClusterManagerClient(credentials=gcp_credentials)

        # Define the parent (project) and cluster ID
        project_id = project  # Update with your GCP project ID
        cluster_id = gke_name  # Ensure this matches the actual cluster name
        location = region # Update if your cluster is in a different location
        print(gke_name)
        print(location)
        print(project_id)
        # Construct the cluster resource name
        cluster_path = f"projects/{project_id}/locations/{location}/clusters/{cluster_id}"

        # Attempt to get information about the cluster
        cluster = client.get_cluster(name=cluster_path)

        if cluster:
            print("The GKE cluster exists.")
            return True
        
    except Exception as e:
        # Print the error message if an exception occurs
        print("An error occurred:", e)
        print("The GKE cluster does not exist or there was an error.")
        return False
 
def store_gke_cluster_info(username, cloudname, region, gke_name):
    cluster_info = gke_cluster(
        username=username,
        cloudname=cloudname,
        region=region,
        eks_name=gke_name
    )
    db.session.add(cluster_info)
    db.session.commit()
@app.route('/submit_form_gcp', methods=['POST'])
def submit_form_gcp():
    if 'jsonFile' not in request.files:
        return json.dumps( {
            "message": 'failed to create key-vault'
        }),409
 
    json_file = request.files['jsonFile']
 
    # Check if the file has a filename
    if json_file.filename == '':
        return render_template('./file_submit.html')
 
    # Check if the file is a JSON file
    if not json_file.filename.endswith('.json'):
        return render_template('./submit.html')
    file_content = json_file.read()
    print(file_content)
    secret_string = file_content.decode('utf-8')
    # clean_secret_string = secret_string.replace('\n', '')
    # secret_dict = json.loads(clean_secret_string)
    # print(secret_dict)
    User_name = request.form.get('User_name')
    account_name = request.form.get('account_name')
    resource_group_name = "Cockpit"  
    key_vault_name = account_name+"gcp"
    new_user = UserAccount(username=User_name, account_name=account_name, cloud_name='gcp')
    db.session.add(new_user)
    db.session.commit()
    location = "eastus"  # Choose a valid Azure location without special characters
    create_key_vault(key_vault_name,location,resource_group_name)
    key_vault = f"https://{key_vault_name}.vault.azure.net/"
    store_secrets(key_vault,"your-secret-name", secret_string)
    store_secrets(key_vault,"username", User_name)
    store_secrets(key_vault,"account-name", account_name)

    return render_template('create_gke.html')

@app.route('/json_submit_form_gcp', methods=['POST'])
def json_submit_form_gcp():
    if 'jsonFile' not in request.files:
        return jsonify({"message": 'No JSON file uploaded'}), 400

    json_file = request.files['jsonFile']

    # Check if the file has a filename
    if json_file.filename == '':
        return jsonify({"message": 'No filename provided for JSON file'}), 400

    # Check if the file is a JSON file
    if not json_file.filename.endswith('.json'):
        return jsonify({"message": 'Uploaded file is not a JSON file'}), 400

    # Read the file content and decode it
    file_content = json_file.read()
    secret_string = file_content.decode('utf-8')

    # Retrieve other form data
    form = request.form
    User_name = form.get('User_name')
    account_name = form.get('account_name')
    location = "eastus"  # Choose a valid Azure location without special characters
    resource_group_name = "Cockpit"  

    # Create key vault
    key_vault_name = account_name + "gcp"
    created = create_key_vault(key_vault_name, location, resource_group_name)
    if not created:
        return jsonify({"message": "These credentials already exist"}), 409

    # Add new user to the database
    new_user = UserAccount(username=User_name, account_name=account_name, cloud_name='gcp')
    db.session.add(new_user)
    db.session.commit()

    # Store secrets in the key vault
    key_vault = f"https://{key_vault_name}.vault.azure.net/"
    store_secrets(key_vault, "your-secret-name", secret_string)
    store_secrets(key_vault, "username", User_name)
    store_secrets(key_vault, "account-name", account_name)

    return jsonify({"message": 'Credentials successfully added', "statusCode": 200})

@app.route('/gcp_form', methods=['GET'])
def gcp_form():
    return render_template('create_gke.html')
 
@app.route('/create_gke_form', methods=['GET'])
def create_gke_form():
    return render_template('create_gke.html')
 
@app.route('/success', methods=['GET'])
def success_gke():
    return render_template('success.html')
 
@app.route('/create_gke', methods=['POST'])
def create_gke():
    # Retrieve form data
    project = request.form.get('project')
    Region = request.form.get('Region')
    gke_name = request.form.get('gke_name')
    gke_version = request.form.get('gke_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')
    
    gke_version = float(gke_version)
 
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None
 
    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'project = "{project}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'gke_name = "{gke_name}"\n')
        f.write(f'gke_version = "{gke_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)
    user = Data(username=user_data["user"], cloudname='gcp', clustername=gke_name)
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}gcp.tfvars'
    file_path = f'/gcp/templates/{file_name}'


    tf_config = f'''
    project = "{project}"
    Region = "{Region}"
    gke_name = "{gke_name}"
    gke_version = "{gke_version}"
    node_count = "{node_count}"
    cluster_type = "{cluster_type}"
    vm_name = "{vm_name}"  
    vm_pass = "{vm_pass}" 
    '''




    # Print the tf_config (optional)
    print("Configuration:", tf_config)

    # Upload the tfvars file to GitLab
    print("Uploading tfvars file to GitLab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tfvars File uploaded successfully")

    # You can also redirect the user to a success page if needed
    
    session['info'] = 'Some information'

    return redirect(url_for('jobs_gcp'))

@app.route('/json_create_gke', methods=['POST'])
def json_create_gke():
    # Retrieve form data
    form = request.get_json()
    account_name = form['account_name']
    project = form['project']
    Region = form['region']
    gke_name = form['gke_name']
    gke_version = form['gke_version']
    node_count = form['node_count']
    cluster_type = form['cluster_type']
    new_username_record = UsernameTablegcp(username=account_name)
    db.session.add(new_username_record)
    db.session.commit()
    gke_version = float(gke_version)
 
    # Initialize variables for vm_name and vm_pass
    vm_name = None
    vm_pass = None
 
    # Process form data based on Cluster Type
    if cluster_type == 'Private':
        vm_name = request.form.get('vm_name')
        vm_pass = request.form.get('vm_pass')
 
    # Create the content for terraform.tfvars
    with open('terraform.tfvars', 'w') as f:
        f.write(f'project = "{project}"\n')
        f.write(f'Region = "{Region}"\n')
        f.write(f'gke_name = "{gke_name}"\n')
        f.write(f'gke_version = "{gke_version}"\n')
        f.write(f'node_count = "{node_count}"\n')
        f.write(f'cluster_type = "{cluster_type}"\n')
        if vm_name is not None:
            f.write(f'vm_name = "{vm_name}"\n')
            f.write(f'vm_pass = "{vm_pass}"\n')

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

    file_name = f'terraform-{account_name}.tfvars'
    file_path = f'gcp/template/{file_name}'


    tf_config = f'''
    project = "{project}"
    region = "{Region}"
    cluster_name = "{gke_name}"
    gke_version = "{gke_version}"
    node_count = "{node_count}"
    cluster_type = "{cluster_type}"
    vm_name = "{vm_name}"  
    vm_pass = "{vm_pass}" 
    '''




    # Print the tf_config (optional)
    print("Configuration:", tf_config)

    # Upload the tfvars file to GitLab
    print("Uploading tfvars file to GitLab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tfvars File uploaded successfully")
    # time.sleep(360)
    print("after 4 mins")
    check_and_store_gke_cluster_status(account_name,"us-central1-f",gke_name,project)
    # You can also redirect the user to a success page if needed
    return json.dumps( {
            "message": 'Pipeline triggered! gke will be created...',
            "statusCode": 200
    })
    #return render_template('success.html')



@app.route("/index")
@login_required
def index():
    todos=todo.query.filter_by(user_id=current_user.id)
    return render_template('index.html',todos=todos)
 
 
@app.route("/about")
def about():
    return render_template('about.html', title='About')


def user_to_dict(user):
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'password': user.password,
        'token': user.token,
        'provider': user.provider
    }

@app.route("/register", methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        user_detail = {
            "user": user_to_dict(user),
        }
        file_name = "user_name.json"
        with open(file_name, 'w') as file:
           json.dump(user_detail, file)
        db.session.add(user)
        db.session.commit()

        
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/jsonRegister", methods=['POST'])
def josnRegister():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = request.get_json()
    if RegistrationJSONForm(form):
        hashed_password = bcrypt.generate_password_hash(form['password']).decode('utf-8')
        user = User(username=form['username'], email=form['email'], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return json.dumps( {
                "message": 'Your account has been created! You are now able to log in ',
                "statusCode": 200
            }), 200
    return json.dumps({
	   "message": 'duplicate username or email',
	   "statusCode": 401
	}), 401
 
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful.', 'success')
            
            # Access the username from the user object and use it as needed
            username = user.username
            
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html', title='Login', form=form)
 
@app.route("/JsonLogin", methods=['POST'])
def JsonLogin():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful.', 'success')

            # Access the username from the user object and use it as needed
            username = user.username
            new_username_record = UsernameTable(username=username)
            user_detail = {
             "user": username,
        
            }
            file_name = "user_name.json"
            with open(file_name, 'w') as file:
               json.dump(user_detail, file)
            

            return jsonify({
                "message": 'Login successful.',
                "statusCode": 200,
                "username": username
            })

        else:
            return jsonify({
                "message": 'Login Unsuccessful. Please check email and password',
                "statusCode": 401
            }), 401

    return jsonify({
        "message": 'Form validation failed.',
        "statusCode": 400
    }), 400
           

@app.route("/logout")
def logout():
    if current_user.is_google_provider:
        token = current_user.get_auth_token()
        requests.post('https://oauth2.googleapis.com/revoke',
            params={'token': token},
            headers = {'content-type': 'application/x-www-form-urlencoded'})

    logout_user()
    flash('Logout successful.', 'success')
    return redirect(url_for('home'))
 
 
 
 
@app.route("/account")
@login_required
def account():
    
    return render_template('account.html', title='Account')
 
@app.route("/add",methods=["POST"])
@login_required
def add():
    user_id=current_user.id
    if request.form['todoitem'] != "" :
        todos=todo(content=request.form['todoitem'],complete=False,user_id=user_id)
        db.session.add(todos)
        db.session.commit()
    else:
        flash('cannot add empty list', 'danger')
        return redirect(url_for("index"))
        
    return redirect(url_for("index"))


@app.route('/eks-output')
def eks_page():
    eks_name = "anuj987"
    region = "US West (N. California)"
    instance_type = "t3.medium"
    eks_version = "1.27"
    desired_size = "2"
    max_size = "2"
    min_size = "2"
    cluster_type = "Private"

    return render_template('eks_page.html', eks_name=eks_name, region=region, instance_type=instance_type,
                           eks_version=eks_version, desired_size=desired_size, max_size=max_size, min_size=min_size,
                           cluster_type=cluster_type)

@app.route('/aks-output')
def aks_page():
    rg_name = "manjari"
    region = "East US"
    availability_zones = "['zone1','zone2']"
    aks_name = "manjari"
    aks_version = "1.24"
    node_count = "1"

    return render_template('aks_page.html', rg_name=rg_name, region=region, availability_zones=availability_zones,
                           aks_name=aks_name, aks_version=aks_version, node_count=node_count)

@app.route('/gke-output')
def gke_page():
    project = "myproject"
    region = "None"
    gke_name = "asdf"
    gke_version = "2.0"
    node_count = "2"
    cluster_type = "Public"
    vm_name = "None"
    vm_pass = "None"

    return render_template('gke_page.html', project=project, region=region, gke_name=gke_name,
                           gke_version=gke_version, node_count=node_count, cluster_type=cluster_type,
                           vm_name=vm_name, vm_pass=vm_pass)






 
 
@app.route("/complete/<int:id>")
@login_required
def complete(id):
    ToDo= todo.query.get(id)
 
    if not ToDo:
        return redirect("/index")
 
    if ToDo.complete:
        ToDo.complete=False
    else:
        ToDo.complete=True
 
    db.session.add(ToDo)
    db.session.commit()
    
    return redirect("/index")
 
@app.route("/delete/<int:id>")
@login_required
def delete(id):
    ToDo=todo.query.get(id)
    if not ToDo:
        return redirect("/index")
    
    db.session.delete(ToDo)
    db.session.commit()
 
    return redirect("/index")
 
 
if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True,host='0.0.0.0',port=4000)
