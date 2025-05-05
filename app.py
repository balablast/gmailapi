import os
from flask import Flask, render_template, jsonify, request, redirect, session, url_for, send_file
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2 import id_token
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport import requests
import base64
from email.mime.text import MIMEText
import os.path
from datetime import datetime
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Get credentials from environment variables
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise ValueError("Missing required environment variables. Please check .env file.")

# OAuth 2.0 client configuration
CLIENT_CONFIG = {
    'web': {
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
        'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
        'redirect_uris': ['http://localhost:5001/oauth2callback']
    }
}

@app.route('/')
def index():
    return render_template('index.html', client_id=GOOGLE_CLIENT_ID)

@app.route('/process_google_login', methods=['POST'])
def process_google_login():
    token = request.json.get('credential')
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        
        # Store the token in session
        session['google_token'] = token
        session['user_email'] = idinfo['email']
        
        return jsonify({'success': True, 'email': idinfo['email']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/emails')
def get_emails():
    if 'google_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        # Create flow instance with client config
        flow = Flow.from_client_config(
            CLIENT_CONFIG,
            scopes=SCOPES,
            redirect_uri='http://localhost:5001/oauth2callback'
        )
        
        credentials = flow.run_local_server(port=0)
        service = build('gmail', 'v1', credentials=credentials)
        
        # Get the last 10 emails
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        
        email_list = []
        for message in messages:
            email_data = get_email_chain(service, message['id'])
            email_list.extend(email_data)
        
        return jsonify({'emails': email_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_email_chain(service, message_id):
    """Get full email chain for a given message ID."""
    email_chain = []
    
    def get_message_data(msg_id):
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        headers = message['payload']['headers']
        
        subject = next(h['value'] for h in headers if h['name'].lower() == 'subject')
        from_header = next(h['value'] for h in headers if h['name'].lower() == 'from')
        date = next(h['value'] for h in headers if h['name'].lower() == 'date')
        
        # Get message body
        if 'parts' in message['payload']:
            parts = message['payload']['parts']
            body = ''
            for part in parts:
                if part['mimeType'] == 'text/plain':
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    break
        else:
            try:
                body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8')
            except:
                body = '[No readable content]'
        
        # Get attachments
        attachments = []
        if 'parts' in message['payload']:
            for part in message['payload']['parts']:
                if 'filename' in part and part['filename']:
                    attachments.append({
                        'id': part['body'].get('attachmentId', ''),
                        'filename': part['filename'],
                        'mimeType': part['mimeType']
                    })
        
        return {
            'id': msg_id,
            'subject': subject,
            'from': from_header,
            'date': date,
            'body': body,
            'attachments': attachments
        }
    
    email_data = get_message_data(message_id)
    email_chain.append(email_data)
    
    return email_chain

@app.route('/download_attachment')
def download_attachment():
    if 'google_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        message_id = request.args.get('message_id')
        attachment_id = request.args.get('attachment_id')
        filename = request.args.get('filename')
        
        # Use the token to access Gmail API (similar to emails route)
        flow = InstalledAppFlow.from_client_config({
            'installed': {
                'client_id': GOOGLE_CLIENT_ID,
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://oauth2.googleapis.com/token',
                'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
                'redirect_uris': ['http://localhost:5001/oauth2callback'],
            }
        }, SCOPES)
        
        credentials = flow.run_local_server(port=0)
        service = build('gmail', 'v1', credentials=credentials)
        
        attachment = service.users().messages().attachments().get(
            userId='me', messageId=message_id, id=attachment_id).execute()
        
        file_data = base64.urlsafe_b64decode(attachment['data'])
        
        # Create temporary file
        temp_path = f'temp_{filename}'
        with open(temp_path, 'wb') as f:
            f.write(file_data)
        
        return send_file(temp_path, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == '__main__':
    app.run(debug=True, port=5001) 