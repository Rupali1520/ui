from flask import Flask, session
import boto3
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
from azure.identity import DefaultAzureCredential
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
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from flask import Flask, jsonify
import hcl
# Your Flask setup code
import re 
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import gitlab
import concurrent.futures
from gitlab.exceptions import GitlabAuthenticationError, GitlabGetError, GitlabListError
from datetime import datetime

gitlab_url = "https://gitlab.com"
project_id = "51819357"
access_token = "glpat-LryS1Hu_2ZX17MSGhgkz"    
branch_name = "featurebrach1"
app = Flask(__name__, static_url_path='/static')

CORS(app) 

app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
# db_config = {
#     'host': 'mysql-service',
#     'user': 'root',
#     'port': 3306,
#     'password': 'cockpitpro',
#     'database': 'jobinfo',
# }

app.config['WTF_CSRF_ENABLED'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:cockpitpro@20.207.117.166:3306/jobinfo'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
 
 
class UsernameTable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f"UsernameTable('{self.username}')"
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    todo = db.relationship('todo', backref='items', lazy=True)
 
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
    return User.query.get(int(user_id))
 
 
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
        'host': '20.207.117.166',
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
        'host': '20.207.117.166',
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

@app.route('/jobs_aws', methods=['GET'])
def jobs_aws():
        username = current_user.username
        job_name = 'aws_infrastructure'
 
        db_config = {
            'host': '20.207.117.166',
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
            created_at = job.created_at_str
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
 
@app.route('/json_jobs_aws', methods=['POST'])
def json_jobs_aws():
    form = request.get_json()
    username = form['username']
    job_name = 'aws_infrastructure'
 
    db_config = {
        'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
    job_name = 'delete_aws_infrastructure'
 
    db_config = {
        'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
        'host': '20.207.117.166',
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
        job_name = 'azure_delete_infrastructure'

        db_config = {
            'host': '20.207.117.166',
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
    job_name = 'azure_delete_infrastructure'

    db_config = {
        'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
        'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
    job_name = 'gcp_delete_infrastructure'

    db_config = {
        'host': '20.207.117.166',
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
        name = username+"aws"
        key_vault_url = f"https://{name}.vault.azure.net/"
    
        # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()

        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_access_key = secret_client.get_secret("secret-Access-key").value
        access_key = secret_client.get_secret("Access-key").value

        return render_template('show-details-aws.html', access_key=access_key, secret_access_key=secret_access_key, username=username)
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
        key_vault_name = username + "aws"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Credential not found."}
            return jsonify(error_msg), 200

        # Key Vault exists, proceed with retrieving secrets
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_access_key = secret_client.get_secret("secret-Access-key").value
        access_key = secret_client.get_secret("Access-key").value

        # Return JSON response
        response_data = {
            "access_key": access_key,
            "secret_access_key": secret_access_key,
            "username": username
        }

        return jsonify(response_data), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "Credentials not found."}
        return jsonify(error_msg), 200

    except HttpResponseError as e:
        # Handle other HTTP response errors
        error_msg = {"error_message": f"HTTP response error: {str(e)}"}
        return jsonify(error_msg), 500

    except Exception as e:
        # Handle other exceptions
        error_msg = {"error_message": f"An error occurred: {str(e)}"}
        return jsonify(error_msg), 500
@app.route('/show-details-azure', methods=['GET', 'POST'])
def show_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        name = username+"azure"
        key_vault_url = f"https://{name}.vault.azure.net/"
    
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
        return render_template('show-details-azure.html', username=username, client_id=client_id, client_secret=client_secret, subscription_id=subscription_id, tenant_id=tenant_id)
        
    else:
        return redirect(url_for('login'))


@app.route('/json-show-details-azure', methods=['POST'])
def json_show_details_azure():
    try:
        form_data = request.get_json()
        username = form_data['username']
        key_vault_name = username + "azure"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Credential not found."}
            return jsonify(error_msg), 200

        # Key Vault exists, proceed with retrieving secrets
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_id = "client-id"
        secret_secret = "client-secret"
        secret_subscription = "subscription-id"
        secret_tenant = "tenant-id"

        client_id = secret_client.get_secret(secret_id).value
        client_secret = secret_client.get_secret(secret_secret).value
        subscription_id = secret_client.get_secret(secret_subscription).value
        tenant_id = secret_client.get_secret(secret_tenant).value

        # Return JSON response
        response_data = {
            "username": username,
            "client_id": client_id,
            "client_secret": client_secret,
            "subscription_id": subscription_id,
            "tenant_id": tenant_id
        }

        return jsonify(response_data), 200

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "Credentials not found."}
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
        name = username+"gcp"
        key_vault_name = f"https://{name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            return render_template('show-details-gcp.html', secret_value="credential not found", username=username)
            # Handle the case when the Key Vault doesn't exist
            # error_msg = {"message": "Credential not found."}
            # return jsonify(error_msg), 200
    # Use DefaultAzureCredential to automatically authenticate
        credential = DefaultAzureCredential()
        
        # Create a SecretClient using the Key Vault URL
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_name = "your-secret-name"
        secret = secret_client.get_secret(secret_name)
        secret_value = secret.value

        return render_template('show-details-gcp.html', secret_value=secret_value, username=username)
        
    else:
        return redirect(url_for('login'))
@app.route('/json-show-details-gcp', methods=['POST'])
def json_show_details_gcp():
    try:
        form_data = request.get_json()
        username = form_data['username']
        key_vault_name = username + "gcp"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)

        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Credential not found."}
            return jsonify(error_msg), 200

        # Key Vault exists, proceed with retrieving secrets
        key_vault_url = f"https://{key_vault_name}.vault.azure.net/"
        credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secrets
        secret_name = "your-secret-name"
        secret = secret_client.get_secret(secret_name)
        secret_value = secret.value

        # Return JSON response
        response_data = {
            "username": username,
            "secret_value": secret_value
        }

        return jsonify(response_data), 200
    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"message": "Credentials not found."}
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

@app.route('/my-cluster-details-aws', methods=['GET', 'POST'])
def my_cluster_details_aws():
    if current_user.is_authenticated:
        username = current_user.username

        # Azure Key Vault details for AWS
        name = username + "aws"

        # Format the Key Vault URL
        key_vault_url_aws = f"https://{name}.vault.azure.net/"

        # Secret names
        access_key_secret = "Access-key"
        secret_access_key_secret = "secret-Access-key"

        try:
            # Retrieve credentials from Azure Key Vault
            credential_aws = DefaultAzureCredential()
            secret_client_aws = SecretClient(vault_url=key_vault_url_aws, credential=credential_aws)

            # Retrieve the secrets from Key Vault
            aws_access_key = secret_client_aws.get_secret(access_key_secret).value
            aws_secret_access_key = secret_client_aws.get_secret(secret_access_key_secret).value

            # Get AWS region from the form data
            region = request.form.get('tenant_id')

            # Set up Boto3 client with retrieved credentials and region
            eks_client = boto3.client(
                'eks',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_access_key,
                region_name='us-east-1'
            )

            clusters_data = []

            # List ready or healthy EKS clusters in the specified AWS region
            eks_clusters = eks_client.list_clusters()
            for cluster_name in eks_clusters['clusters']:
                cluster_info = eks_client.describe_cluster(name=cluster_name)
                if cluster_info['cluster']['status'] == 'ACTIVE':
                    clusters_data.append({"name": cluster_name})

            return render_template('my-cluster-details-aws.html', username=username, cluster=clusters_data)
        except Exception as e:
            # Print error details and traceback
            print(f"Error in my_cluster_details_aws: {str(e)}")
            traceback.print_exc()

            # Return an error response or redirect as needed
            return render_template('error.html', error_message="An error occurred. Please try again later.")
    else:
        return redirect(url_for('login'))

@app.route('/json-my-cluster-details-aws', methods=['POST'])
def json_my_cluster_details_aws():
        form = request.get_json()
        username = form['username']

        # Azure Key Vault details for AWS
        name = username + "aws"

        # Format the Key Vault URL
        key_vault_url_aws = f"https://{name}.vault.azure.net/"

        # Secret names
        access_key_secret = "Access-key"
        secret_access_key_secret = "secret-Access-key"

        try:
            # Retrieve credentials from Azure Key Vault
            credential_aws = DefaultAzureCredential()
            secret_client_aws = SecretClient(vault_url=key_vault_url_aws, credential=credential_aws)

            # Retrieve the secrets from Key Vault
            aws_access_key = secret_client_aws.get_secret(access_key_secret).value
            aws_secret_access_key = secret_client_aws.get_secret(secret_access_key_secret).value

            # Get AWS region from the form data
            region = request.form.get('tenant_id')

            # Set up Boto3 client with retrieved credentials and region
            eks_client = boto3.client(
                'eks',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_access_key,
                region_name='us-east-1'
            )

            clusters_data = []

            # List ready or healthy EKS clusters in the specified AWS region
            eks_clusters = eks_client.list_clusters()
            for cluster_name in eks_clusters['clusters']:
                cluster_info = eks_client.describe_cluster(name=cluster_name)
                if cluster_info['cluster']['status'] == 'ACTIVE':
                    clusters_data.append({"name": cluster_name})

            if not clusters_data:
            # Handle the case when there are no clusters
              return jsonify({"username": username, "clusters": [], "message": "No clusters available."}), 200

            return jsonify({"username": username, "clusters": clusters_data}),200
        except Exception as e:
            # Print error details and traceback
            print(f"Error in my_cluster_details_aws: {str(e)}")
            traceback.print_exc()

            # Return an error response or redirect as needed
            return jsonify({"error_message": "An error occurred. Please try again later."}),404


@app.route('/my-cluster-details', methods=['GET', 'POST'])
def my_cluster_details():
    if current_user.is_authenticated:
        username = current_user.username
        return render_template('my-cluster-details.html', username=username)
    else:
        return redirect(url_for('login'))



        # Print healthy or ready AKS clusters
        # print("Healthy Azure Kubernetes Service Clusters:")
        # for aks_cluster in aks_clusters:
        #     if aks_cluster.provisioning_state.lower() == "succeeded" and aks_cluster.agent_pool_profiles[0].provisioning_state.lower() == "succeeded":
        #         print(f" - {aks_cluster.name}")

@app.route('/my-cluster-details-azure', methods=['GET', 'POST'])
def my_cluster_details_azure():
    if current_user.is_authenticated:
        username = current_user.username
        name = username + "azure"
        key_vault_url = f"https://{name}.vault.azure.net/"
        secrets = ["client-id", "client-secret", "subscription-id", "tenant-id"]

        try:
            # Retrieve credentials from Azure Key Vault
            credential = DefaultAzureCredential()
            # Create a SecretClient using the Key Vault URL
            secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

            # Retrieve the secrets from Key Vault
            secrets_values = {secret: secret_client.get_secret(secret).value for secret in secrets}

            # Set up the ContainerServiceClient with retrieved credentials
            aks_client = ContainerServiceClient(credential, secrets_values["subscription-id"])

            # Your logic to list Azure Kubernetes Service Clusters here
            aks_clusters = [cluster.name for cluster in aks_client.managed_clusters.list()]

            return render_template('my-cluster-details-azure.html', username=username, aks_clusters=aks_clusters)
        except Exception as e:
            print(f"Error: {str(e)}")
            # Handle the exception appropriately, e.g., return an error page
            return render_template('error.html', error_message=str(e))
    else:
        return redirect(url_for('login'))



   

from flask import jsonify
@app.route('/json-my-cluster-details-azure', methods=['POST'])
def json_my_cluster_details_azure():
    form = request.get_json()
    username = form['username']

    try:
        # Query the database to get AKS cluster names for the given username
        aks_names = aks_cluster.query.filter_by(username=username).with_entities(aks_cluster.aks_name).all()
        
        # Extract AKS names from the query result
        aks_names = [result[0] for result in aks_names]

        # Check if there are no AKS clusters available
        if not aks_names:
            return jsonify({"username": username, "message": "No AKS clusters available for the given user."}), 200

        # Return JSON response with AKS cluster names
        return jsonify({"username": username, "aks_cluster": aks_names}), 200

    except Exception as e:
        # Handle other exceptions (e.g., database connection error)
        print(f"Error: {str(e)}")
        return jsonify({"error_message": "An error occurred while fetching AKS cluster details."}), 500
@app.route('/json-my-cluster-details-gcp', methods=['POST'])
def json_my_cluster_details_gcp():
    # if current_user.is_authenticated:
      
        form = request.get_json()
        username = form['username']
        name = username + "gcp"

            # Azure Key Vault details for GCP
        key_vault_url_gcp = f"https://{name}.vault.azure.net/"
        gcp_credentials_secret = "your-secret-name"  # Update with your actual secret name
        try:
            # Retrieve credentials from Azure Key Vault
                credential_gcp = DefaultAzureCredential()
                secret_client_gcp = SecretClient(vault_url=key_vault_url_gcp, credential=credential_gcp)

                    # Retrieve the GCP credentials JSON from Key Vault
                gcp_credentials_json = secret_client_gcp.get_secret(gcp_credentials_secret).value

                    # Parse the JSON string into a dictionary
                gcp_credentials_dict = json.loads(gcp_credentials_json)

                    # Use the parsed dictionary to create a service account credentials object
                gcp_credentials = service_account.Credentials.from_service_account_info(gcp_credentials_dict)
                # except Exception as e:
                #     print(f"Error retrieving or parsing GCP credentials: {e}")
                    # Use the service account credentials for the discovery build
                service = discovery.build('container', 'v1', credentials=gcp_credentials)
                gcp_projects = ['golden-plateau-401906']

                    # List to store GKE clusters data
                clusters_data = []

                for project in gcp_projects:
                    requests = service.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
                    response = requests.execute()

                    if 'clusters' in response:
                        for cluster in response['clusters']:
                            clusters_data.append({cluster['name']})

                    # Return JSON response
                return jsonify({"username": username, "clusters_data": clusters_data}), 200
        except Exception as e:
            print(f"Error: {str(e)}")
            return jsonify({"error_message": "cluster not found"}),200


@app.route('/my-cluster-details-gcp', methods=['GET', 'POST'])
def my_cluster_details_gcp():
    if current_user.is_authenticated:
        username = current_user.username
        name = username +"gcp"
        # Azure Key Vault details for GCP
        key_vault_url_gcp = f"https://{name}.vault.azure.net/"
        gcp_credentials_secret = "your-secret-name"  # Update with your actual secret name

        # Retrieve credentials from Azure Key Vault
        credential_gcp = DefaultAzureCredential()
        secret_client_gcp = SecretClient(vault_url=key_vault_url_gcp, credential=credential_gcp)

        # Retrieve the GCP credentials JSON from Key Vault
        gcp_credentials_json = secret_client_gcp.get_secret(gcp_credentials_secret).value

            # Parse the JSON string into a dictionary
        gcp_credentials_dict = json.loads(gcp_credentials_json)

            # Use the parsed dictionary to create a service account credentials object
        gcp_credentials = service_account.Credentials.from_service_account_info(gcp_credentials_dict)
        

        # Use the service account credentials for the discovery build
        service = discovery.build('container', 'v1', credentials=gcp_credentials)
        gcp_projects = ['golden-plateau-401906']

        # List to store GKE clusters data
        clusters_data = []

        for project in gcp_projects:
            request = service.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
            response = request.execute()

            if 'clusters' in response:
                for cluster in response['clusters']:
                    clusters_data.append({cluster['name']})
        return render_template('my-cluster-details-gcp.html', username=username, clusters_data=clusters_data)
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
            'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
            'host': '20.207.117.166',
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
def aws():
    return render_template('aws.html')
@app.route('/aws1')
def aws1():
    return render_template('aws1.html')
@app.route('/aws2')
def aws2():
    return render_template('aws2.html')
@app.route('/delete_aws_credential', methods=['POST'])
def delete_aws_credential():
    User_name = request.form.get('User_name')
    key_vault_name = User_name+"aws"
    resource_group = "Cockpit"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
 
    return render_template('final-dashboard.html')
@app.route('/json_delete_aws_credential', methods=['POST'])
def json_delete_aws_credential():
    try:
        form = request.get_json()
        User_name = form['user_name']
        key_vault_name = User_name+"aws"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Invaild username."}
            return jsonify(error_msg), 404
        delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', 'Cockpit', key_vault_name)
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
        key_vault_name = User_name+"aws"
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
    key_vault_name = User_name+"aws"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "Access-key", Access_key)
    update_keyvault_secret(vault_url, "secret-Access-key", secret_Access_key)
 
    return render_template('final-dashboard.html')

@app.route('/json_submit_form_aws', methods=['POST'])
def json_submit_form_aws():
# Get  AWS form data
    
    form = request.get_json()
    Access_key = form['access_key']
    secret_Access_key = form['secret_access_key']
    User_name = form['user_name']
    User_Id = str(int(random.random()))

    user_detail = {
        "user": User_name,
        
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)
 
 
 
    # Write AWS form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'Username = "{User_name}"\n')
        f.write(f'Access_key = "{Access_key}"\n')
        f.write(f'secret_Access_key = "{secret_Access_key}"\n')
    
 
     ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "Cockpit"  
    key_vault_name = User_name+"aws"
    secrets_file_path = "./terraform.tfvars"
 
    
 
    # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")
 
    
    subscription_id = 'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5'
    client_id = 'ad3b9e95-c03c-4728-840e-cbd8c75ea353'
    client_secret = 'p268Q~SIJlP6FViKhI.M4B6d7dB5Tr95PZHYqczI'
    tenant_id = '097b85e8-2f0c-4726-a9d5-af15f7621ce5'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    with open("./terraform.tfvars", "r") as file:
       for line in file:
          if line.strip().startswith('Access_key'):
             key, value = line.strip().split(" = ")
             Access_key = value    
    
 
    
    keyvaults = keyvault_client.vaults.list()
    for vault in keyvaults:
        vault_name = vault.name
        keyvault_url = f"https://{vault_name}.vault.azure.net/"
        Accesskey = SecretClient(vault_url=keyvault_url, credential=credential)
        key_name = "Access_key"
        try:
          key = Accesskey.get_secret(key_name)
          key_value = key.value
         # decoded_bytes = base64.b64decode(key_value)
         # decoded_string = decoded_bytes.decode('utf-8')
          if key_value == Access_key:
                print(f"Key Vault '{vault_name}' has the matching secret: '{key_name}'")
                matching_secret_found = True
                break 
        except Exception as e:
             print(f"Key Vault '{vault_name}' does not contain the secret: '{key_name}'")
    if not matching_secret_found:
       print("No matching secret found in any of the Key Vaults.")
       
    # Authenticate to Azure
       try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
       except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
       
 
    # Create Azure Key Vault in the specified Resource Group
       try:
        subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
        print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
       except subprocess.CalledProcessError:
        print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
 
    
 
    # Store secrets in Azure Key Vault
       for key, value in secrets.items():
        # Replace underscores with hyphens in the secret name
         key = key.replace("_", "-")
         #encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
         #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
         command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
    
 
         try:
            # Use Azure CLI to set the secret in the Key Vault
            subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
            print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
         except subprocess.CalledProcessError as e:
            print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
            print(e)
 
    
 
       print("All secrets have been stored in Azure Key Vault.")
    
 
       os.remove(secrets_file_path)     
    
 
       with open(secrets_file_path, "w"):         pass
 
    ## ending the script
       return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
       }) 
    #return render_template('./create_aws.html')
 
@app.route('/submit_form', methods=['POST'])
def submit_form_aws():
# Get  AWS form data

    Access_key = request.form.get('Access_key')
    secret_Access_key = request.form.get('secret_Access_key')
    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))

    user_detail = {
        "user": User_name,
        
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)
 
 
 
    # Write AWS form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'Username = "{User_name}"\n')
        f.write(f'Access_key = "{Access_key}"\n')
        f.write(f'secret_Access_key = "{secret_Access_key}"\n')
    
 
     ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "Cockpit"  
    key_vault_name = User_name+"aws"
    secrets_file_path = "./terraform.tfvars"
 
    
 
    # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")
 
    
    subscription_id = 'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5'
    client_id = 'ad3b9e95-c03c-4728-840e-cbd8c75ea353'
    client_secret = 'p268Q~SIJlP6FViKhI.M4B6d7dB5Tr95PZHYqczI'
    tenant_id = '097b85e8-2f0c-4726-a9d5-af15f7621ce5'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    
    
 
    
 
    # Authenticate to Azure
    try:
        # Use Azure CLI to get the access token
        access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
        exit(1)
 
 
    # Create Azure Key Vault in the specified Resource Group
    try:
        subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
        print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
    except subprocess.CalledProcessError:
        print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
 
    
 
    # Store secrets in Azure Key Vault
    for key, value in secrets.items():
        # Replace underscores with hyphens in the secret name
        key = key.replace("_", "-")
        #encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
        #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
        command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
    
 
        try:
            # Use Azure CLI to set the secret in the Key Vault
            subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
            print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
            print(e)
 
    
 
    print("All secrets have been stored in Azure Key Vault.")
    
 
    os.remove(secrets_file_path)     
    
 
    with open(secrets_file_path, "w"):         pass
 
    ## ending the script
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
    
    aks_name = request.form.get('aks_name')
    resource_group = request.form.get('resource_group')
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
        check_and_delete_aks(username=user_data["user"],resource_group=resource_group,aks_name=aks_name)
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
        aks_name = form['aks_name']
        resource_group = form['resource_group']
 
        file_path = 'azure-delete/file.txt'
        tf_config = f''' 
        aks_name = "{aks_name}"
        resource_group = "{resource_group}"
        '''
 
        print("Configuration:", tf_config)
        print("Uploading tf file to GitLab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        file_name = "./user_name.json"
        with open(file_name, 'r') as file:
            user_data = json.load(file)
        check_and_delete_aks(username=user_data["user"], resource_group=resource_group, aks_name=aks_name)
        response_data = {'status': 'success', 'message': 'Delete request triggered the pipeline, please wait some time...'}
        return jsonify(response_data), 200
 
    except Exception as e:
        # For other exceptions, you might want to log the full exception details
        response_data = {'status': 'error', 'message': str(e)}
        return jsonify(response_data), 404



@app.route('/delete_gke', methods=['POST'])
def delete_gke():
    gke_name = request.form.get('gke_name')
    region = request.form.get('region')
    projecct_id = request.form.get('project_id')
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
    file_content_normalized = file_content.strip().replace('\r\n', '\n')
    tf_config_normalized = tf_config.strip().replace('\r\n', '\n')
    if file_content_normalized == tf_config_normalized:
        print("same contant")
        return render_template('gcp_del.html')
    else:
        print("Uploading tf file to gitlab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        return render_template('success.html')

@app.route('/json_delete_gke', methods=['POST'])
def json_delete_gke():
  try:
    gke_name = request.form.get('gke_name')
    region = request.form.get('region')
    project_id = request.form.get('project_id')

    with open('file.txt', 'w') as f:
        f.write(f'gke-name = "{gke_name}"\n')
        f.write(f'region = "{region}"\n')
        f.write(f'project_id = "{project_id}"\n')
    
    file_path = f'gke-delete/file.txt'
    tf_config = f''' 
    gke_name = "{gke_name}"
    region = "{region}"
    project_id = "{project_id}"
    '''
    print("Configuration:", tf_config)
    print("Uploading tf file to gitlab")
    upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
    print("Tf File uploaded successfully")
    response_data = {'status': 'success', 'message': 'Delete request triggered the pipeline please wait sometime...'}
    return jsonify(response_data),202

  except Exception as e:
        error_message = f"An error occurred: {str(e)}"
        response_data = {'status': 'error', 'message': error_message}
        return jsonify(response_data),404




@app.route('/delete_eks', methods=['POST'])
def delete_eks():
    
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
    if file_content_normalized == tf_config_normalized:
        print("same contant")
        return render_template('aws_del.html')
    else:
        print("Uploading tf file to gitlab")
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
        print("Tf File uploaded successfully")
        return render_template('success.html')

@app.route('/json_delete_eks', methods=['POST'])
def json_delete_eks():
    try:
        form = request.get_json()
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
        upload_file_to_gitlab(file_path, tf_config, project_id, access_token, gitlab_url, branch_name)
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
    # Retrieve form data
    form = request.get_json()
    eks_name = form['cluster_name']
    Region = form['region']
    instance_type = form['instance_type']
    eks_version = form['eks_version']
    desired_size = form['desired_size']
    max_size = form['max_size']
    min_size = form['min_size']
    cluster_type = form['cluster_type']
    
    # user = Data(username=user_data["user"], cloudname='aws', clustername=user_data["eks_name"])
    # db.session.add(user)
    # db.session.commit()
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

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)

    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'aws/templates/{file_name}'

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


    # You can also redirect the user to a success page if needed
    return json.dumps({
        "message": "pipeline triggerd eks will be created..."
    })


@app.route('/create_aws', methods=['POST'])
def create_aws():

    # Retrieve form data
    eks_name = request.form.get('cluster_name')
    Region = request.form.get('region')
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

    file_name = "./user_name.json"

    with open(file_name, 'r') as file:
        user_data = json.load(file)
  
    user = Data(username=user_data["user"], cloudname='aws', clustername=eks_name)
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}.tfvars'
    file_path = f'aws/templates/{file_name}'

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
    # You can also redirect the user to a success page if needed
    session['info'] = 'Some information'

    return redirect(url_for('jobs_aws'))
 
#azure form
@app.route('/azure')
def azure():
    return render_template('azure.html')

@app.route('/azure1')
def azure1():
    return render_template('azure1.html')

@app.route('/azure2')
def azure2():
    return render_template('azure2.html')
@app.route('/delete_azure_credential', methods=['POST'])
def delete_azure_credential():
    User_name = request.form.get('User_name')
    key_vault_name = User_name+"azure"
    resource_group = "Cockpit"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
    return render_template('final-dashboard.html')
@app.route('/json_delete_azure_credential', methods=['POST'])
def json_delete_azure_credential():
    try:
        form = request.get_json()
        User_name = form['User_name']
        key_vault_name = User_name + "azure"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        resource_group = "Cockpit"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
            # Handle the case when the Key Vault doesn't exist
            error_msg = {"error message": "Invaild Username."}
            return jsonify(error_msg), 404
        
        delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
        
        return json.dumps({
            "message": 'Credential delete successfully',
            "statusCode": 200
        })

    except ResourceNotFoundError:
        # Handle the case when a specific secret doesn't exist
        error_msg = {"error message": "Invaild Username."}
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

    # # Delete all secrets from the Key Vault
    # secrets = secret_client.list_properties_of_secrets()
    # for secret in secrets:
    #     secret_client.begin_delete_secret(secret.name).wait()

    # # Purge the deleted secrets
    # deleted_secrets = secret_client.list_deleted_secrets()
    # for deleted_secret in deleted_secrets:
    #     secret_client.purge_deleted_secret(deleted_secret.name)

    # Finally, delete the Key Vault itself
    client = KeyVaultManagementClient(credential, subscription_id)
    client.vaults.delete(resource_group, keyvault_name)

@app.route('/update_azure_credential', methods=['POST'])
def update_azure_credential():
    subscription_id = request.form.get('subscription_id')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    tenant_id = request.form.get('tenant_id')
    User_name = request.form.get('User_name')
    key_vault_name = User_name+"azure"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "client-id", client_id)
    update_keyvault_secret(vault_url, "client-secret", client_secret)
    update_keyvault_secret(vault_url, "tenant-id", tenant_id)
    update_keyvault_secret(vault_url, "subscription-id", subscription_id)
    return render_template('final-dashboard.html')

def update_keyvault_secret(vault_url, secret_name, new_secret_value):
    # Authenticate using DefaultAzureCredential
    credential = DefaultAzureCredential()

    # Create a SecretClient using the Key Vault URL
    secret_client = SecretClient(vault_url=vault_url, credential=credential)

    # Get the existing secret to obtain its metadata
    existing_secret = secret_client.get_secret(secret_name)

    # Update the secret with the new value
    updated_secret = secret_client.set_secret(secret_name, new_secret_value)

    print(f"Secret '{secret_name}' updated successfully.")
    print(f"Old Secret Value: {existing_secret.value}")
    print(f"New Secret Value: {updated_secret.value}")
@app.route('/submit_form_azure', methods=['POST'])
def submit_form_azure():
    # Get  azure form data
    subscription_id = request.form.get('subscription_id')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    tenant_id = request.form.get('tenant_id')
    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))
   
    # Write Azure form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'username = "{User_name}"\n')
        f.write(f'subscription_id = "{subscription_id}"\n')
        f.write(f'client_id = "{client_id}"\n')
        f.write(f'client_secret = "{client_secret}"\n')
        f.write(f'tenant_id = "{tenant_id}"\n')
   
    ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "Cockpit"  
    key_vault_name = User_name+"azure"
    secrets_file_path = "./terraform.tfvars"


    user_detail = {
        "user": User_name
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)

 
   # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")    
    subscription_id = 'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5'
    client_id = 'ad3b9e95-c03c-4728-840e-cbd8c75ea353'
    client_secret = 'p268Q~SIJlP6FViKhI.M4B6d7dB5Tr95PZHYqczI'
    tenant_id = '097b85e8-2f0c-4726-a9d5-af15f7621ce5'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    with open("./terraform.tfvars", "r") as file:
     for line in file:
        if line.strip().startswith('client_secret'):
            key, value = line.strip().split(' = ')
            # print(value)
            client_secret = value
 
    # print (client_secret)
 
    keyvaults = keyvault_client.vaults.list()
    for vault in keyvaults:
        vault_name = vault.name
        keyvault_url = f"https://{vault_name}.vault.azure.net/"
        secret_client = SecretClient(vault_url=keyvault_url, credential=credential)
        secret_name = "client-secret"
        try:
            secret = secret_client.get_secret(secret_name)
            secret_value = secret.value
          #  decoded_bytes = base64.b64decode(secret_value)
         #   decoded_string = decoded_bytes.decode('utf-8')
            # print(decoded_string)
            if secret_value == client_secret:
                print(f"Key Vault '{vault_name}' has the matching secret: '{secret_name}'")
                matching_secret_found = True
                break  # Stop the loop when a matching secret is found
        except Exception as e:
            print(f"Key Vault '{vault_name}' does not contain the secret: '{secret_name}'")
    if not matching_secret_found:
        print("No matching secret found in any of the Key Vaults.")
 
    # Authenticate to Azure
 
        try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
 
        # Create Azure Key Vault in the specified Resource Group
        try:
            subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
            print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
        except subprocess.CalledProcessError:
            print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
 
        
        # Store secrets in Azure Key Vault
        for key, value in secrets.items():
            # Replace underscores with hyphens in the secret name
            key = key.replace("_", "-")
            #encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
            #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
            command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
            try:
                # Use Azure CLI to set the secret in the Key Vault
                subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
                print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
                print(e)
 
        
        print("All secrets have been stored in Azure Key Vault.")
        
        os.remove(secrets_file_path)     
        
        with open(secrets_file_path, "w"):         pass
    
    ## ending the script

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
        key_vault_name = User_name + "azure"
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
    User_Id = str(int(random.random()))
 
    # Write Azure form data to terraform.vars file
    with open('terraform.tfvars', 'w') as f:
        f.write(f'username = "{User_name}"\n')
        f.write(f'subscription_id = "{subscription_id}"\n')
        f.write(f'client_id = "{client_id}"\n')
        f.write(f'client_secret = "{client_secret}"\n')
        f.write(f'tenant_id = "{tenant_id}"\n')
   
    ## starting the script
 
    # Azure Resource Group and Key Vault Configuration
    resource_group_name = "Cockpit"  
    key_vault_name = User_name+"azure"
    secrets_file_path = "./terraform.tfvars"


    user_detail = {
        "user": User_name,
        
    }

    print("User name:", User_name)

    file_name = "user_name.json"

    with open(file_name, 'w') as file:
        json.dump(user_detail, file)

    

 
   # Replace underscores with hyphens in the Key Vault and Resource Group names
    key_vault_name = key_vault_name.replace("_", "-")
    resource_group_name = resource_group_name.replace("_", "-")    
    subscription_id = 'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5'
    client_id = 'ad3b9e95-c03c-4728-840e-cbd8c75ea353'
    client_secret = 'p268Q~SIJlP6FViKhI.M4B6d7dB5Tr95PZHYqczI'
    tenant_id = '097b85e8-2f0c-4726-a9d5-af15f7621ce5'
    matching_secret_found = False
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    # Read secrets from the file
    secrets = {}
    with open(secrets_file_path, "r") as file:
        for line in file:
            key, value = line.strip().split(" = ")
            secrets[key] = value
    with open("./terraform.tfvars", "r") as file:
     for line in file:
        if line.strip().startswith('client_secret'):
            key, value = line.strip().split(' = ')
            # print(value)
            client_secret = value
 
    # print (client_secret)
 
    keyvaults = keyvault_client.vaults.list()
    for vault in keyvaults:
        vault_name = vault.name
        keyvault_url = f"https://{vault_name}.vault.azure.net/"
        secret_client = SecretClient(vault_url=keyvault_url, credential=credential)
        secret_name = "client-secret"
        try:
            secret = secret_client.get_secret(secret_name)
            secret_value = secret.value
            #decoded_bytes = base64.b64decode(secret_value)
            #decoded_string = decoded_bytes.decode('utf-8')
            # print(decoded_string)
            if secret_value == client_secret:
                print(f"Key Vault '{vault_name}' has the matching secret: '{secret_name}'")
                matching_secret_found = True
                break  # Stop the loop when a matching secret is found
        except Exception as e:
            print(f"Key Vault '{vault_name}' does not contain the secret: '{secret_name}'")
    if not matching_secret_found:
        print("No matching secret found in any of the Key Vaults.")
 
    # Authenticate to Azure
 
        try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
        except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
 
        # Create Azure Key Vault in the specified Resource Group
        try:
            subprocess.check_call(["az", "keyvault", "create", "--name", key_vault_name, "--resource-group", resource_group_name, "--location", "southcentralus"])
            print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
        except subprocess.CalledProcessError:
            print(f"Azure Key Vault '{key_vault_name}' already exists or encountered an error during creation in Resource Group '{resource_group_name}'.")
            return json.dumps({
                "message" : "Azure Key Vault '{}' already exists or encountered an error during creation in Resource Group '{}'".format(key_vault_name, resource_group_name)
            }),200
 
        
        # Store secrets in Azure Key Vault
        for key, value in secrets.items():
            # Replace underscores with hyphens in the secret name
            key = key.replace("_", "-")
           # encoded_value = base64.b64encode(value.encode("utf-8")).decode("utf-8")     
            #command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {encoded_value} --output none --query 'value'"
            command = f"az keyvault secret set --vault-name {key_vault_name} --name {key} --value {value} --output none --query 'value'"
 
            try:
                # Use Azure CLI to set the secret in the Key Vault
                subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
                print(f"Secret '{key}' stored in Azure Key Vault '{key_vault_name}' successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to store secret '{key}' in Azure Key Vault '{key_vault_name}'.")
                print(e)
 
        
        print("All secrets have been stored in Azure Key Vault.")
        
        os.remove(secrets_file_path)     
        
        with open(secrets_file_path, "w"):         pass
     
    ## ending the script

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
 
 
    print("user name is:", user_data["user"])
    user = Data(username=user_data["user"], cloudname='azure', clustername=user_data["aks_name"])
    db.session.add(user)
    db.session.commit()
    file_name = f'terraform-{user_data["user"]}.tfvars'
    
 
    
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
    check_and_store_aks_cluster_status(username=user_data["user"],resource_group=resource_group,aks_name=aks_name,Region=Region)
 
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

    file_name = f'terraform-{user_data["user"]}.tfvars'
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
    check_and_store_aks_cluster_status(username=user_data["user"],resource_group=resource_group,aks_name=aks_name,Region=Region)

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
    try:
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
        save_directory = './'
        file_path = os.path.join(save_directory, json_file.filename)
        json_file.save(file_path)
        secrets_file_path = file_path
        
        with open(secrets_file_path, 'r') as json_file:
            secrets_content = json_file.read()
        form = request.get_json()
        
        User_name = form['user_name']
        key_vault_name = User_name+"gcp"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "First Add Credential."}
            return jsonify(error_msg), 404
        update_keyvault_secret(vault_url, "your-secret-name", secrets_content)
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
@app.route('/delete_credential_gcp', methods=['POST'])
def delete_credential_gcp():
    User_name = request.form.get('User_name')
    key_vault_name = User_name
    resource_group = "Cockpit"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', resource_group, key_vault_name)
    return render_template('final-dashboard.html')
@app.route('/json_delete_credential_gcp', methods=['POST'])
def json_delete_credential_gcp():
    try:
        form = request.get_json()
        User_name = form['user_name']
        key_vault_name = User_name+"gcp"
        vault_url = f"https://{key_vault_name}.vault.azure.net/"
        key_vault_exists = check_key_vault_existence("f1aed9cb-fcad-472f-b14a-b1a0223fa5a5", "Cockpit", key_vault_name)
        if not key_vault_exists:
                # Handle the case when the Key Vault doesn't exist
            error_msg = {"message": "Invaild username."}
            return jsonify(error_msg), 404
        delete_keyvault(vault_url,'f1aed9cb-fcad-472f-b14a-b1a0223fa5a5', 'Cockpit', key_vault_name)
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
@app.route('/update_credential_gcp', methods=['GET'])
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
    save_directory = './'
    file_path = os.path.join(save_directory, json_file.filename)
    json_file.save(file_path)
    secrets_file_path = file_path
    
    with open(secrets_file_path, 'r') as json_file:
        secrets_content = json_file.read()
 
    User_name = request.form.get('User_name')
    key_vault_name = User_name+"gcp"
    vault_url = f"https://{key_vault_name}.vault.azure.net/"
    update_keyvault_secret(vault_url, "your-secret-name", secrets_content)

    return render_template('final-dashboard.html')
@app.route('/submit_form_gke', methods=['GET'])
def create_gcp():
    # Retrieve form data
    project = request.form.get('project')
    Region = request.form.get('Region')
    gke_name = request.form.get('gke_name')
    gke_version = request.form.get('gke_version')
    node_count = request.form.get('node_count')
    cluster_type = request.form.get('cluster_type')
    gke_version = str(gke_version)
    gke_version = version.parse(gke_version)
 
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
    
    return render_template('success.html')

@app.route('/submit_form_gke', methods=['POST'])
def submit_form_gcp():
    # Check if a file was uploaded
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
    # Specify the directory where you want to save the JSON file
    save_directory = './'
 
    # Save the JSON file with its original filename
    json_file.save(f"{save_directory}/{json_file.filename}")
 
    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))
 
    # Azure Key Vault and Secrets Configuration
    key_vault_name = User_name+"gcp"
 
    resource_group_name = "Cockpit"
    location = "westus2"
    secrets_file_path = json_file.filename
 
        # Create Azure Key Vault if it doesn't exist
    create_kv_command = f"az keyvault create --name {key_vault_name} --resource-group {resource_group_name} --location {location}"
    try:
            subprocess.check_output(create_kv_command, shell=True)
            print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
    except subprocess.CalledProcessError:
            print(f"Error: Failed to create Azure Key Vault.")
            exit(1)
 
        # Authenticate to Azure
    try:
            # Use Azure CLI to get the access token
            access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
            print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
            exit(1)
 
        # Read the entire content of the JSON file
    with open(secrets_file_path, 'r') as json_file:
            secrets_content = json_file.read()
 
 
        # Store the entire JSON content as a secret
    secret_name = "your-secret"
    # encoded_value = base64.b64encode(secrets_content.encode("utf-8")).decode("utf-8")     
    # command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value '{encoded_value}' --output none --query 'value'"
          # Replace with your desired secret name
    command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value '{secrets_content}' --output none --query 'value'"
    try:
            # Use Azure CLI to set the secret in the Key Vault
            subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
            print(f"Secret '{secret_name}' has been stored in Azure Key Vault.")
    except subprocess.CalledProcessError as e:
            print(f"Error: Failed to store secret '{secret_name}' in Azure Key Vault.")
            print(e)
 
        
 
    print("Secret has been stored in Azure Key Vault.")
    os.remove(secrets_file_path)    
 
    
    return json.dumps( {
            "message": 'Credential Succesfully added',
            "statusCode": 200
    })
   # return render_template('create_gke.html')

@app.route('/json_submit_form_gke', methods=['POST'])
def json_submit_form_gcp():
    # Check if a file was uploaded
    if 'jsonFile' not in request.files:
        return jsonify({"message": 'No file part'}), 400

    json_file = request.files['jsonFile']

    # Check if the file has a filename
    if json_file.filename == '':
        return jsonify({"message": 'No file selected'}), 400

    # Check if the file is a JSON file
  #  if not json_file.filename.endswith('.json'):
   #     return jsonify({"message": 'Invalid file type. Please upload a JSON file'}), 400

    # Specify the directory where you want to save the JSON file
    save_directory = './'

    # Save the JSON file with its original filename
    file_path = os.path.join(save_directory, json_file.filename)
    json_file.save(file_path)

    User_name = request.form.get('User_name')
    User_Id = str(int(random.random()))

    # Azure Key Vault and Secrets Configuration
    key_vault_name = User_name+"gcp"
    resource_group_name = "Cockpit"
    location = "westus2"
    secrets_file_path = file_path

    # Create Azure Key Vault if it doesn't exist
    create_kv_command = f"az keyvault create --name {key_vault_name} --resource-group {resource_group_name} --location {location}"
    try:
        subprocess.check_output(create_kv_command, shell=True)
        print(f"Azure Key Vault '{key_vault_name}' created successfully in Resource Group '{resource_group_name}'.")
    except subprocess.CalledProcessError:
        print(f"Error: Failed to create Azure Key Vault.")
        os.remove(file_path)  # Remove the uploaded file if creation of Key Vault fails
        return jsonify({"message": 'Failed to create Azure Key Vault'}), 500

    # Authenticate to Azure
    try:
        access_token = subprocess.check_output(["az", "account", "get-access-token", "--query", "accessToken", "-o", "tsv"]).decode("utf-8").strip()
    except subprocess.CalledProcessError:
        print("Error: Failed to obtain Azure access token. Make sure you are logged into Azure CLI.")
        os.remove(file_path)  # Remove the uploaded file if access token retrieval fails
        return jsonify({"message": 'Failed to obtain Azure access token'}), 500

    # Read the entire content of the JSON file
    with open(secrets_file_path, 'r') as json_file:
        secrets_content = json_file.read()

    # Store the entire JSON content as a secret
    secret_name = "your-secret-name"
    encoded_value = base64.b64encode(secrets_content.encode("utf-8")).decode("utf-8")
    command = f"az keyvault secret set --vault-name {key_vault_name} --name {secret_name} --value {encoded_value} --output none --query 'value'"

    try:
        subprocess.check_call(["bash", "-c", f'AZURE_ACCESS_TOKEN="{access_token}" {command}'])
        print(f"Secret '{secret_name}' has been stored in Azure Key Vault.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to store secret '{secret_name}' in Azure Key Vault. {e}")
        os.remove(file_path)  # Remove the uploaded file if storing secret fails
        return jsonify({"message": 'Failed to store secret in Azure Key Vault'}), 500

    print("Secret has been stored in Azure Key Vault.")
    os.remove(file_path)  # Remove the uploaded file after processing

    return jsonify({"message": 'Credential Successfully added', "statusCode": 200})





#gcp
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
    project = form['project']
    Region = form['Region']
    gke_name = form['gke_name']
    gke_version = form['gke_version']
    node_count = form['node_count']
    cluster_type = form['cluster_type']
    
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

    file_name = f'terraform-{user_data["user"]}gcp.tfvars'
    file_path = f'gcp/template/{file_name}'


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
 
@app.route("/register", methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        user_detail = {
             "user": user,
        
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
   #     flash('Your account has been created! You are now able to log in', 'success')
    #    return redirect(url_for('login'))
    #return render_template('register.html', title='Register', form=form)
    #return json.dumps({
     #      "message": 'Invalid or not mathced with defined expression',
      #     "statusCode": 401
       # }), 401
# @app.route("/login", methods=['GET', 'POST'])#
# def login():
#   if current_user.is_authenticated:
#        return redirect(url_for('dashboard'))
#   form = LoginForm()
#   if form.validate_on_submit():
#      user = User.query.filter_by(email=form.email.data).first()
#      if user and bcrypt.check_password_hash(user.password, form.password.data):
#          login_user(user, remember=form.remember.data)
#          next_page = request.args.get('next')
#          flash('Login successful.', 'success')
#          return redirect(next_page) if next_page else redirect(url_for('dashboard'))
#      else:
#             flash('Login Unsuccessful. Please check email and password', 'danger')
#   return render_template('login.html', title='Login', form=form)
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
            new_username_record = UsernameTable(username=username)
            db.session.add(new_username_record)
            db.session.commit()
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
            db.session.add(new_username_record)
            db.session.commit()

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
    app.run(debug=True,host='0.0.0.0',port=4000)
