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

# Load credentials from file
CLIENT_SECRETS_FILE = "client_secret_893994365037-d3v55cjl5hnffln47g3dlru3b5n6ke8j.apps.googleusercontent.com.json"

def get_flow():
    return InstalledAppFlow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:5001/oauth2callback'
    )

@app.route('/')
def index():
    if 'credentials' not in session:
        flow = get_flow()
        auth_url, _ = flow.authorization_url(access_type='offline', include_granted_scopes='true')
        return render_template('index.html', auth_url=auth_url, authenticated=False)
    else:
        return render_template('index.html', authenticated=True)

@app.route('/oauth2callback')
def oauth2callback():
    flow = get_flow()
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    # Redirect back to index, adding a hash to trigger email loading
    return redirect(url_for('index') + '#authenticated')

@app.route('/emails')
def get_emails():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        credentials = Credentials(**session['credentials'])
        service = build('gmail', 'v1', credentials=credentials)
        
        # Get the last 20 emails
        results = service.users().messages().list(userId='me', maxResults=20).execute()
        messages = results.get('messages', [])
        
        email_list = []
        if not messages:
            print("No messages found.")
        else:
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id'], format='metadata', metadataHeaders=['Subject', 'From', 'Date']).execute()
                headers = msg['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'No Sender')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'No Date')
                email_list.append({
                    'id': msg['id'],
                    'subject': subject,
                    'from': from_header,
                    'date': date,
                    'snippet': msg.get('snippet', '')
                })
        
        return jsonify({'emails': email_list})
    except Exception as e:
        print(f"Error fetching emails: {e}")
        return jsonify({'error': str(e)}), 500

def parse_email_body(parts):
    """Parses email parts to find plain text or HTML body."""
    body = ""
    if parts:
        for part in parts:
            mimeType = part.get('mimeType')
            part_body = part.get('body')
            data = part_body.get('data')
            if mimeType == "text/plain" and data:
                body = base64.urlsafe_b64decode(data).decode('utf-8')
                break # Prefer plain text
            elif mimeType == "text/html" and data:
                # Decode HTML as fallback if plain text not found
                if not body:
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
            # Recursively check nested parts
            if "parts" in part:
                nested_body = parse_email_body(part["parts"])
                if nested_body:
                    body = nested_body
                    if mimeType == "text/plain": # Stop if we found plain text deeper
                        break
    return body

@app.route('/email/<message_id>')
def get_email_details(message_id):
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        credentials = Credentials(**session['credentials'])
        service = build('gmail', 'v1', credentials=credentials)

        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = message.get('payload', {})
        headers = payload.get('headers', [])

        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        from_header = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'No Sender')
        date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'No Date')

        body = ""
        if 'parts' in payload:
            body = parse_email_body(payload['parts'])
        elif 'body' in payload and payload['body'].get('data'):
            body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
            # Check if the main body itself is plain text
            if payload.get('mimeType') != 'text/plain':
                 # If not plain text, might need further parsing or could be HTML
                 # For simplicity, we'll assume it's displayable or was handled above
                 pass # Consider adding HTML tag stripping if needed
        
        attachments = []
        if 'parts' in payload:
            for part in payload['parts']:
                 # Check recursively for attachments
                 part_queue = [part]
                 while part_queue:
                     current_part = part_queue.pop(0)
                     if current_part.get('filename'):
                         att_id = current_part.get('body', {}).get('attachmentId')
                         if att_id:
                             attachments.append({
                                 'id': att_id,
                                 'filename': current_part.get('filename'),
                                 'mimeType': current_part.get('mimeType')
                             })
                     if 'parts' in current_part:
                         part_queue.extend(current_part['parts'])


        email_details = {
            'id': message_id,
            'subject': subject,
            'from': from_header,
            'date': date,
            'body': body, # Contains parsed plain text or HTML
            'attachments': attachments
        }

        return jsonify(email_details)

    except Exception as e:
        print(f"Error fetching email details for {message_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download_attachment')
def download_attachment():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    try:
        message_id = request.args.get('message_id')
        attachment_id = request.args.get('attachment_id')
        filename = request.args.get('filename')
        
        credentials = Credentials(**session['credentials'])
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
        # Ensure temp_path exists before trying to remove it
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == '__main__':
    app.run(debug=True, port=5001) 