import tweepy

API_KEY = "T5evvALwAXJQY1rW9CmD408n0"
API_SECRET = "DGtjfDHQWLMUzDjCI12cDXfHxI6kR7I3eVles92i8BDk0SJaKA"

auth = tweepy.OAuth1UserHandler(API_KEY, API_SECRET, callback="oob")

try:
    auth_url = auth.get_authorization_url()
    print("1. Open this URL in your web browser:")
    print(auth_url)
    print("\n2. MAKE SURE YOU ARE LOGGED INTO YOUR NEW BOT ACCOUNT IN THAT BROWSER!")
    print("3. Click 'Authorize app'.")
    print("4. Copy the PIN number Twitter gives you.")
    
    pin = input("\nPaste the PIN here and press Enter: ")
    
    access_token, access_token_secret = auth.get_access_token(pin)
    
    print("\nSUCCESS! Here are your bot's unique tokens:")
    print(f'X_ACCESS_TOKEN = "{access_token}"')
    print(f'X_ACCESS_TOKEN_SECRET = "{access_token_secret}"')

except Exception as e:
    print(f"Error: {e}")