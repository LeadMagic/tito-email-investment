import os
import base64
import re
import logging
from email import message_from_bytes
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import httpx
import openai
import asyncio

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Set up logging
logging.basicConfig(level=logging.DEBUG, filename='gmail_cold_email_filter.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

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
        if phrase in email.body or phrase in email.subject:
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

def main():
    service = authenticate_gmail()
    messages = get_emails(service)

    openai_key = input("Enter your OpenAI API key: ")
    gpt_prompt = input("Enter your GPT prompt: ")

    for msg in messages:
        try:
            email_from, is_cold_email, analysis_result, confidence_score = analyze_email(service, msg['id'], openai_key, gpt_prompt)
            logging.info(f"Email from {email_from} analyzed. Cold email: {is_cold_email}. Confidence score: {confidence_score}. Analysis result: {analysis_result}")

            if is_cold_email:
                move_to_promotions(service, msg['id'])
                domain = email_from.split('@')[-1]
                domain_info = asyncio.run(get_domain_info(domain))

                if domain_info:
                    creation_date = datetime.utcfromtimestamp(domain_info['creation_date']).strftime('%Y-%m-%d')
                    logging.info(f"Domain {domain} was registered on {creation_date}")
                    print(f"Domain {domain} was registered on {creation_date}")

        except Exception as e:
            logging.error(f"Error processing email {msg['id']}: {e}")

if __name__ == '__main__':
    main()
