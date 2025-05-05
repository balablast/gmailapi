# Gmail Chain Extractor

This application allows you to extract email chains and attachments from your Gmail account.

## Setup

1. Create a Google Cloud Project and enable the Gmail API
2. Download your OAuth 2.0 credentials and save them as `credentials.json` in the project root
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:5000`
3. Authenticate with your Google account
4. View and download your email chains and attachments

## Security Note
- The application uses OAuth 2.0 for secure authentication
- Credentials are stored locally and not shared
- Make sure to keep your `credentials.json` and `.env` file secure 