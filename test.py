import requests

# API endpoint
url = 'http://localhost:5000/get_message/user1'  # Change 'user1' to the desired username

# Send GET request
response = requests.get(url)

# Check response
if response.status_code == 200:
    data = response.json()
    print("Username:", data['username'])
    print("Encrypted Message:", data['encrypted_message'])
else:
    print("Error:", response.json())
