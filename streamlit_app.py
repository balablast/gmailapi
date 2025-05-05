import streamlit as st
import os
import base64
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from datetime import datetime # Added for date parsing
import traceback # For detailed error logging

# --- Configuration ---
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = "client_secret_893994365037-d3v55cjl5hnffln47g3dlru3b5n6ke8j.apps.googleusercontent.com.json"
# REDIRECT_URI = "http://localhost:8501" # Not strictly needed for OOB flow
# TOKEN_FILE = "token.json" # Not using file storage for simplicity

# --- Helper Functions ---

def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def get_credentials():
    creds = None
    if 'credentials' in st.session_state:
        creds_dict = st.session_state['credentials']
        try:
            creds = Credentials(**creds_dict)
        except Exception as e:
            st.error(f"Error loading credentials from session state: {e}")
            del st.session_state['credentials']
            return None

    if creds and creds.valid:
        return creds
    elif creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            st.session_state['credentials'] = credentials_to_dict(creds)
            # Don't show success on refresh, keep UI clean
            # st.success("Credentials refreshed successfully.") 
            return creds
        except Exception as e:
            st.error(f"Error refreshing token: {e}")
            if 'credentials' in st.session_state: del st.session_state['credentials']
            if 'auth_flow_active' in st.session_state: del st.session_state['auth_flow_active']
            st.rerun()
            return None
    else:
        return None

def authenticate():
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, 
            SCOPES,
            redirect_uri='urn:ietf:wg:oauth:2.0:oob'
            )
        auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline', include_granted_scopes='true')
        st.session_state['auth_flow_active'] = True
        st.session_state['auth_url'] = auth_url
        st.session_state['flow'] = flow
    except FileNotFoundError:
        st.error(f"Credentials file not found: {CLIENT_SECRETS_FILE}. Please ensure it's in the same directory.")
        st.stop()
    except Exception as e:
        st.error(f"Error initiating authentication: {e}")
        st.stop()

def format_date(date_str):
    """Parse date string and format it, handle potential errors."""
    if not date_str: return "No Date"
    try:
        # Handle potential timezone offsets like -0700 (PDT)
        # Python's %z directive requires specific formats, so try common ones
        date_obj = None
        formats_to_try = [
            "%a, %d %b %Y %H:%M:%S %z", # Standard format with timezone offset
            "%d %b %Y %H:%M:%S %z",    # Format without weekday
            "%a, %d %b %Y %H:%M:%S %Z", # Format with timezone name (might be less reliable)
            "%Y-%m-%dT%H:%M:%S%z"       # ISO 8601 format (if applicable)
        ]
        for fmt in formats_to_try:
            try:
                date_obj = datetime.strptime(date_str.split(' (')[0].strip(), fmt) # Remove trailing info like (PDT)
                break
            except ValueError:
                continue
        
        if date_obj:
            return date_obj.strftime("%Y-%m-%d %H:%M")
        else:
             # Fallback if specific parsing fails
            return date_str 
    except Exception:
        # Broad catch for unexpected date formats
        return date_str # Return original if parsing fails

def parse_email_body(parts):
    """Parses email parts to find plain text or HTML body."""
    body = ""
    if parts:
        for part in parts:
            mimeType = part.get('mimeType')
            part_body = part.get('body')
            data = part_body.get('data')
            # Prioritize plain text
            if mimeType == "text/plain" and data:
                body = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                return body # Return immediately once plain text is found
            # Recurse for multipart types
            elif mimeType.startswith("multipart/") and "parts" in part:
                nested_body = parse_email_body(part["parts"])
                if nested_body: # Found something in nested parts
                    return nested_body
            # Fallback to HTML if no plain text found yet
            elif mimeType == "text/html" and data and not body:
                body = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                # Continue searching in case plain text exists elsewhere in this level

    return body # Return whatever was found (HTML or empty)


@st.cache_data(ttl=600) # Cache email list for 10 minutes
def fetch_emails(_creds_dict, max_results=20):
    """Fetches a list of emails with metadata."""
    try:
        creds = Credentials(**_creds_dict)
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])
        
        email_list = []
        if not messages:
            st.info("No messages found.")
            return []
        else:
            # Fetch metadata for each message
            batch = service.new_batch_http_request()
            email_details = {}

            def callback(request_id, response, exception):
                if exception is None:
                    email_details[request_id] = response
                else:
                    print(f"Error fetching message {request_id}: {exception}")

            for i, message in enumerate(messages):
                batch.add(
                    service.users().messages().get(
                        userId='me', 
                        id=message['id'], 
                        format='metadata', 
                        metadataHeaders=['Subject', 'From', 'Date']
                    ),
                    callback=callback,
                    request_id=message['id']
                )
            batch.execute()
            
            # Process batch results
            for msg_id in email_details:
                msg = email_details[msg_id]
                headers = msg.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'No Sender')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'No Date')
                email_list.append({
                    'id': msg['id'],
                    'subject': subject,
                    'from': from_header,
                    'date': format_date(date),
                    'snippet': msg.get('snippet', '')
                })
            return email_list
    except Exception as e:
        st.error(f"Error fetching emails: {e}")
        traceback.print_exc() # Print full traceback to console
        return None # Indicate error

@st.cache_data(ttl=3600) # Cache individual emails for 1 hour
def fetch_email_details(_creds_dict, message_id):
    """Fetches full details for a single email."""
    try:
        creds = Credentials(**_creds_dict)
        service = build('gmail', 'v1', credentials=creds)
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
            # If the main payload has body data, try decoding it
             raw_body_data = payload['body']['data']
             body = base64.urlsafe_b64decode(raw_body_data).decode('utf-8', errors='replace')

        if not body: # Fallback if parsing failed or body was empty
            body = "[No readable content found]"

        attachments = []
        if 'parts' in payload:
            part_queue = list(payload['parts']) # Start with top-level parts
            while part_queue:
                part = part_queue.pop(0)
                if part.get('filename'):
                    body_info = part.get('body', {})
                    att_id = body_info.get('attachmentId')
                    att_size = body_info.get('size', 0)
                    if att_id:
                        attachments.append({
                            'id': att_id,
                            'filename': part.get('filename'),
                            'mimeType': part.get('mimeType'),
                            'size': att_size
                        })
                # Recursively add nested parts to the queue
                if 'parts' in part:
                    part_queue.extend(part['parts'])

        return {
            'id': message_id,
            'subject': subject,
            'from': from_header,
            'date': format_date(date),
            'body': body,
            'attachments': attachments
        }
    except Exception as e:
        st.error(f"Error fetching email details for {message_id}: {e}")
        traceback.print_exc() # Print full traceback to console
        return None

def fetch_attachment(_creds_dict, message_id, attachment_id):
    """Fetches attachment data."""
    try:
        creds = Credentials(**_creds_dict)
        service = build('gmail', 'v1', credentials=creds)
        attachment = service.users().messages().attachments().get(
            userId='me', messageId=message_id, id=attachment_id).execute()
        file_data = base64.urlsafe_b64decode(attachment['data'])
        return file_data
    except Exception as e:
        st.error(f"Error downloading attachment: {e}")
        traceback.print_exc() # Print full traceback to console
        return None

# --- Streamlit App Layout ---
st.set_page_config(layout="wide")
st.title("Gmail Chain Extractor (Streamlit)")

# Initialize session state variables if they don't exist
if 'selected_email_id' not in st.session_state:
    st.session_state.selected_email_id = None
if 'email_list' not in st.session_state:
    st.session_state.email_list = None

# --- Authentication Flow ---
creds = get_credentials()

if not creds:
    st.warning("You need to authorize this app to access your Gmail data.")
    col1, col2 = st.columns([1, 5]) # Button smaller column
    with col1:
        if st.button("Sign in with Google"):
            authenticate()
            st.rerun()
    
    if st.session_state.get('auth_flow_active', False):
        st.markdown(f'Please go to this [URL]({st.session_state.get("auth_url", "#")}) to authorize.', unsafe_allow_html=True)
        auth_code = st.text_input("Enter the authorization code you received here:")
        
        if auth_code:
            flow = st.session_state.get('flow')
            if flow:
                try:
                    flow.fetch_token(code=auth_code)
                    creds = flow.credentials
                    st.session_state['credentials'] = credentials_to_dict(creds)
                    # Clean up auth flow state and rerun
                    del st.session_state['auth_flow_active']
                    if 'auth_url' in st.session_state: del st.session_state['auth_url']
                    if 'flow' in st.session_state: del st.session_state['flow']
                    st.success("Authentication successful!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error fetching token: {e}. Make sure you copied the code correctly.")
                    # Reset auth state on error
                    if 'auth_flow_active' in st.session_state: del st.session_state['auth_flow_active']
                    if 'flow' in st.session_state: del st.session_state['flow']
            else:
                 st.error("Authentication flow state lost. Please try signing in again.")
                 if 'auth_flow_active' in st.session_state: del st.session_state['auth_flow_active']

else:
    # --- Main Application View (Authenticated) ---
    
    # Sign Out Button (place it prominently, maybe sidebar or top columns)
    # Using columns to place sign out button nicely
    col_main, col_signout = st.columns([0.85, 0.15])
    with col_signout:
        if st.button("Sign Out"):
            # Clear all relevant session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    # --- Display Selected Email Details FIRST if an email is selected ---
    if st.session_state.selected_email_id:
        with col_main:
             st.header("Email Details")
        # Use a placeholder while fetching
        details_placeholder = st.empty()
        with details_placeholder.container():
             with st.spinner("Loading details..."):
                 # Pass credentials dict to cached function
                 details = fetch_email_details(st.session_state['credentials'], st.session_state.selected_email_id)

        if details:
            # Clear the placeholder and display the expander
            details_placeholder.empty()
            # Display details within the main column
            with col_main:
                with st.container(): # Use a container for better grouping
                    st.write(f"**From:** {details['from']}")
                    st.write(f"**Date:** {details['date']}")
                    st.write(f"**Subject:** {details['subject']}")
                    st.markdown("--- Body ---")
                    st.markdown(details['body'], unsafe_allow_html=True)

                    st.markdown("--- Attachments ---")
                    if details['attachments']:
                        for att in details['attachments']:
                            st.download_button(
                                label=f"Download {att['filename']} ({att.get('size', 0)} bytes)",
                                data=fetch_attachment(st.session_state['credentials'], details['id'], att['id']), 
                                file_name=att['filename'],
                                mime=att.get('mimeType', 'application/octet-stream'),
                                key=f"dl_{details['id']}_{att['id']}"
                            )
                    else:
                        st.write("No attachments found.")
                    
                    st.markdown("---") # Separator before close button
                    if st.button("Close Details", key=f"close_{details['id']}"):
                        st.session_state.selected_email_id = None
                        st.rerun()
        else:
            # Clear the placeholder and show error
            details_placeholder.empty()
            with col_main: # Show error in the main column
                 st.error("Could not load email details.")
                 if st.button("Clear Selection"):
                      st.session_state.selected_email_id = None 
                      st.rerun()
        
        # Add a separator before the inbox list when details are shown
        st.markdown("***") 
        st.markdown("&nbsp;") # Add some space

    # --- Display Inbox List (Always shown below details or if no details selected) ---
    # Fetch email list if not already in session state (or if details just closed)
    # The fetch logic remains the same but runs after potential detail view
    if st.session_state.email_list is None and not st.session_state.selected_email_id:
        with col_main: # Show spinner in main column
             with st.spinner("Fetching emails..."):
                 email_list = fetch_emails(st.session_state['credentials'])
                 if email_list is not None:
                      st.session_state.email_list = email_list
                 else:
                      st.session_state.email_list = [] 
    
    with col_main: # Display list header in main column
        st.header("Your Inbox")
        
    # Display Email List in the main column
    if st.session_state.email_list:
        for email in st.session_state.email_list:
            # Use columns within the main display area
            list_cols = st.columns([0.4, 0.4, 0.2]) 
            with list_cols[0]:
                st.markdown(f"**{email.get('subject', 'No Subject')}**")
                st.caption(f"{email.get('from', 'No Sender')}")
            with list_cols[1]:
                 st.caption(f"{email.get('snippet', '...')}")
            with list_cols[2]:
                 st.caption(email.get('date', 'No Date'))
                 if st.button("View", key=f"view_{email['id']}"):
                     st.session_state.selected_email_id = email['id']
                     # Clear email list cache when viewing details to ensure it refetches if needed later
                     if 'email_list' in st.session_state: 
                          del st.session_state['email_list']
                     st.rerun() 
            st.markdown("---")
    elif st.session_state.email_list is not None: # Only show if fetch was attempted
        with col_main:
             st.info("No emails to display or failed to fetch emails.") 