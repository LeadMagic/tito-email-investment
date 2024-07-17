# 📧 The Ultimate Cold Email Filter with Domain Age Check

Cost:

API-Ninjas is $15/mo
Host the Python Script on Vercel, Fly, Railway (most likely for free)

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



## 📚 Documentation

- **Gmail API**: [Gmail API Python Quickstart](https://developers.google.com/gmail/api/quickstart/python)
- **OpenAI API**: [OpenAI API Documentation](https://beta.openai.com/docs/)
- **Supabase**: [Supabase Documentation](https://supabase.io/docs)
- **API Ninjas**: [API Ninjas Documentation](https://api-ninjas.com/api/whois)

## 📫 Contact

For more information or questions, feel free to connect with me on [LinkedIn](https://linkedin.com/in/jesseoue).

This project was created to help you manage and filter cold emails efficiently, ensuring that your inbox remains clean and relevant. Happy filtering! ✨

Developed with ❤️ by Jesse Ouellette
