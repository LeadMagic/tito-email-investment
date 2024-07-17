# 📧 Cold Email Filter with Domain Age Check

This Python script checks your Gmail inbox for cold emails and moves them to the promotions folder if the sending domain is under 2 years old and not whitelisted in the Supabase database. It uses the Gmail API, OpenAI for email content analysis, and API Ninjas for WHOIS lookup. The script logs all actions and provides a comprehensive email filtering solution.

![Cold Email Filter](https://images.unsplash.com/photo-1561408035-0a151962a284?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=MnwzNjUyOXwwfDF8c2VhcmNofDN8fGVtYWlsJTIwZmlsdGVyfGVufDB8fHx8MTY5MTI5NjUxNQ&ixlib=rb-1.2.1&q=80&w=1080)

## 🛠️ Features

- **Gmail Integration**: Connects to your Gmail account to read emails.
- **Cold Email Detection**: Uses predefined keywords and phrases to classify emails.
- **Domain Age Check**: Checks if the domain is under 2 years old.
- **Whitelist Management**: Maintains a whitelist of safe domains in Supabase.
- **OpenAI Integration**: Analyzes email content using OpenAI's GPT-3.
- **Logging**: Logs all actions and analysis results.

## 📝 Prerequisites

- Python 3.7+
- Gmail API credentials
- OpenAI API key
- Supabase account and API key
- API Ninjas key for WHOIS lookup

## 📦 Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-repo/cold-email-filter.git
    cd cold-email-filter
    ```

2. **Install required libraries**:
    ```bash
    pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib dnspython httpx openai supabase
    ```

3. **Set up Gmail API**:
   - Follow the [Gmail API Python Quickstart guide](https://developers.google.com/gmail/api/quickstart/python) to create a project in the Google Developers Console, enable the Gmail API, and download the `credentials.json` file.

4. **Configure Supabase**:
   - Create a table named `domain_whitelist` with a `domain` column in your Supabase project.
   - Replace `'YOUR_SUPABASE_KEY'` with your actual Supabase API key in the script.

5. **Replace API keys in the script**:
   - Replace `'YOUR_SUPABASE_KEY'`, `'YOUR_API_NINJAS_API_KEY'`, and `'YOUR_OPENAI_API_KEY'` with your actual keys.

## 🚀 Usage

1. **Run the script**:
    ```bash
    python gmail_cold_email_filter.py
    ```

2. **Authenticate**:
   - The first time you run the script, it will open a browser window to authenticate your Google account and give the necessary permissions.

3. **Provide API keys**:
   - Enter your OpenAI API key and the GPT prompt when prompted by the script.

## 🤖 Script Overview

```python
# The script connects to Gmail, analyzes emails, and moves cold emails to the promotions folder
import os
import base64
import re
import logging
from email import message_from_bytes
from datetime import datetime, timezone
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import httpx
import openai
import asyncio
from supabase import create_client, Client

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Set up logging
logging.basicConfig(level=logging.DEBUG, filename='gmail_cold_email_filter.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

# Initialize Supabase client
supabase_url = 'https://tzebizglbnmrdbzlskyp.supabase.co'
supabase_key = 'YOUR_SUPABASE_KEY'
supabase: Client = create_client(supabase_url, supabase_key)

class Email:
    def __init__(self, subject, body, sender):
        self.subject = subject
        self.body = body
        self.sender = sender

def authenticate_gmail():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_emails(service):
    results = service.users().messages().list(userId='me', q='').execute()
    messages = results.get('messages', [])
    return messages

def classify_email(email):
    cold_email_keywords = [
        "offer", "services", "solutions", "boost your business", "scale your product",
        "expert developers", "top-notch digital marketing", "business growth",
        "job opportunity", "exciting role", "came across your profile", "recruitment",
        "investment opportunity", "interested in discussing", "potential investment", "analyst at"
    ]

    legitimate_phrases = [
        "great meeting you at", "thanks for your help with",
        "question about your product", "issue with",
        "monthly newsletter", "latest updates from",
        "password reset request", "welcome to", "purchase receipt from"
    ]

    # Initialize score
    confidence_score = 0

    # Check for cold email keywords
    for keyword in cold_email_keywords:
        if keyword in email.body or keyword in email.subject:
            confidence_score += 10  # Increase score for each cold email keyword found

    # Check for legitimate phrases
    for phrase in legitimate_phrases:
        if phrase in email.body or email.subject:
            confidence_score -= 20  # Decrease score for each legitimate phrase found

    # Determine if email is cold
    is_cold_email = confidence_score > 0

    return {
        "confidence_score": confidence_score,
        "is_cold_email": is_cold_email
    }

def analyze_email(service, msg_id, openai_key, gpt_prompt):
    message = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
    msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
    mime_msg = message_from_bytes(msg_str)

    email_from = mime_msg['from']
    email_subject = mime_msg['subject']
    email_body = mime_msg.get_payload()

    email = Email(subject=email_subject, body=email_body, sender=email_from)

    classification_result = classify_email(email)

    # Send email body to OpenAI for analysis
    openai.api_key = openai_key
    response = openai.Completion.create(
        engine="text-davinci-003",
        prompt=gpt_prompt + "\n\n" + email_body,
        max_tokens=150
    )
    analysis_result = response.choices[0].text.strip()

    return email_from, classification_result["is_cold_email"], analysis_result, classification_result["confidence_score"]

def move_to_promotions(service, msg_id):
    service.users().messages().modify(
        userId='me',
        id=msg_id,
        body={'addLabelIds': ['CATEGORY_PROMOTIONS']}
    ).execute()

async def get_domain_info(domain):
    api_url = f"https://api.api-ninjas.com/v1/whois?domain={domain}"
    headers = {'X-Api-Key': 'YOUR_API_NINJAS_API_KEY'}
    async with httpx.AsyncClient() as client:
        response = await client.get(api_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Error fetching WHOIS data for {domain}: {response.text}")
            return None

def is_domain_whitelisted(domain):
    response = supabase.table('domain_whitelist').select('domain').eq('domain', domain).execute()
    return len(response.data) > 0

def add_domain_to_whitelist(domain):
    supabase.table('domain_whitelist').insert({'domain': domain}).execute()

def create_whitelist_table():
    supabase.table('domain_whitelist').create_table(
        columns=[
            {'name': 'domain', 'type': 'text', 'primary': True}
        ],
        if_not_exists=True
    ).execute()

def main():
    create_whitelist_table()
    
    service = authenticate_gmail()
    messages = get_emails(service)

    openai_key = input("Enter your OpenAI API key: ")
    gpt_prompt = input("Enter your GPT prompt: ")

    for msg in messages:
        try:
            email_from, is_cold_email, analysis_result, confidence_score = analyze_email(service, msg['id'], openai_key, gpt_prompt)
            logging.info(f"Email from {email_from} analyzed. Cold email: {is_cold_email}. Confidence score: {confidence_score}. Analysis result: {analysis_result}")

            if is_cold_email:
                domain = email_from.split('@')[-1]

                if not is_domain_whitelisted(domain):
                    domain_info = asyncio.run(get_domain_info(domain))

                    if domain_info:
                        creation_date = datetime.utcfromtimestamp(domain_info['creation_date']).replace(tzinfo=timezone.utc)
                        current_date = datetime.now(timezone.utc)
                        domain_age = (current_date - creation_date).days

                        if domain_age <= 730:  # 2 years in days
                            logging.info(f"Domain {domain} is under 2 years old and not whitelisted.")
                            move_to_promotions(service, msg['id'])
                        else:
                            logging.info(f"Domain {domain} is older than 2 years.")
                    else:
                        logging.error(f"Could not retrieve domain info for {domain}.")
                else:
                    logging.info(f"Domain {domain} is whitelisted.")
            else:
                logging.info(f"Email from {email_from} is not a cold email.")

        except Exception as e:
            logging.error(f"Error processing email {msg['id']}: {e}")

if __name__ == '__main__':
    main()


## 📚 Documentation

- **Gmail API**: [Gmail API Python Quickstart](https://developers.google.com/gmail/api/quickstart/python)
- **OpenAI API**: [OpenAI API Documentation](https://beta.openai.com/docs/)
- **Supabase**: [Supabase Documentation](https://supabase.io/docs)
- **API Ninjas**: [API Ninjas Documentation](https://api-ninjas.com/api/whois)

## 📫 Contact

For more information or questions, feel free to connect with me on [LinkedIn](https://linkedin.com/in/jesseoue).

This project was created to help you manage and filter cold emails efficiently, ensuring that your inbox remains clean and relevant. Happy filtering! ✨

Developed with ❤️ by Jesse Ouellette
