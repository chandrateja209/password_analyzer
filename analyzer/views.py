import secrets
import string
import math
import hashlib
import requests
from django.shortcuts import render

# API URL to check leaked passwords
PWNED_API_URL = "https://api.pwnedpasswords.com/range/"

# Approximate guesses per second (adjustable based on attack power)
GUESSES_PER_SECOND = 1_000_000_000  # 1 billion guesses per second

def home(request):
    result = None  
    password = None  
    strength_class = ""  
    crack_time = None  
    leaked_count = 0  

    if request.method == "POST":
        if "generate" in request.POST or not request.POST.get('password', '').strip():
            password = generate_password()
        else:
            password = request.POST.get('password')

        result, strength_class, crack_time = check_password_strength(password)
        leaked_count = check_leaked_password(password)

    return render(request, 'analyzer/home.html', {
        'result': result, 
        'password': password, 
        'strength_class': strength_class,
        'crack_time': crack_time,
        'leaked_count': leaked_count
    })

def check_password_strength(password):
    length = len(password)
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    # Estimate character set size
    char_pool = 26  
    if has_upper: char_pool += 26
    if has_digit: char_pool += 10
    if has_special: char_pool += len(string.punctuation)

    # Calculate entropy
    entropy = math.log2(char_pool ** length)
    crack_seconds = 2 ** entropy / GUESSES_PER_SECOND
    crack_time = format_crack_time(crack_seconds)

    # Add 2FA Suggestion for Weak Passwords
    if length < 6:
        return "Weak 😞 (Too Short) - Enable 2FA!", "weak", crack_time
    elif length < 10 or not (has_upper and has_lower and has_digit and has_special):
        return "Moderate 🙂 (Could be stronger) - Consider 2FA", "moderate", crack_time
    else:
        return "Strong 💪 (Good Job!)", "strong", crack_time

def format_crack_time(seconds):
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    elif seconds < 3153600000:
        return f"{seconds / 31536000:.2f} years"
    else:
        return f"{seconds / 3153600000:.2f} centuries"

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if check_password_strength(password)[1] == "strong":
            return password

def check_leaked_password(password):
    """Check if the password has been leaked using Have I Been Pwned API."""
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    try:
        response = requests.get(PWNED_API_URL + prefix)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for line in hashes:
                hash_suffix, count = line.split(":")
                if suffix == hash_suffix:
                    return int(count)  # Return number of times leaked
        return 0  # Password not found in leaks
    except requests.RequestException:
        return -1  # Indicates a network issue
