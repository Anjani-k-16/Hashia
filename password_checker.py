import re
import math
import hashlib
import requests
from zxcvbn import zxcvbn 


# --- CORE FUNCTION 1: SHANNON ENTROPY ---
def calculate_entropy(password):
    """Calculates Shannon Entropy in bits for a given password."""
    
    R = 0
    if re.search(r'[a-z]', password):
        R += 26  
    if re.search(r'[A-Z]', password):
        R += 26  
    if re.search(r'[0-9]', password):
        R += 10  
    if re.search(r'[!@#$%^&*()_+=\-{}[\]:;"\'<,>.?/\\|`~]', password):
        R += 33 
    
    if R == 0:
        return 0
        
    L = len(password)
    entropy = L * math.log2(R)
    
    return round(entropy, 2)


# --- CORE FUNCTION 2: HAVE I BEEN PWNED ---
def check_for_breach(password):
    """
    Checks if the password is found in the HIBP database using k-anonymity.
    Returns (is_pwned: bool, pwn_count: int)
    """
    
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    prefix = sha1password[:5]
    suffix = sha1password[5:]
    
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() 
        
        lines = response.text.splitlines()
        for line in lines:
            if line.startswith(suffix):
                count = int(line.split(':')[1].strip())
                return (True, count)
        
    except requests.exceptions.RequestException as e:
        print(f"\n[Warning] Could not connect to HIBP API: {e}")
        return (False, 0)
        
    return (False, 0)


# --- CORE FUNCTION 3: ZXCVBN STRENGTH ESTIMATOR ---
def check_realistic_strength(password):
    """
    Uses the zxcvbn library to provide a realistic strength score (0-4)
    and time-to-crack estimation.
    """
    return zxcvbn(password)


# --- MAIN EXECUTION LOGIC (Updated for professionalism and bug fix) ---
def get_password_input():
    """Handles user input, performs checks, and outputs the result."""
    while True:
        password = input("\nEnter a password to check (or 'quit' to exit): ")
        
        # 1. Check for quit command
        if password.lower() == 'quit':
            break
            
        # 2. CRITICAL FIX: Handle empty or whitespace-only input
        if not password.strip():
            print("\n[Input Error] Please enter a valid password (cannot be empty).")
            continue 
        
        # 3. Run all three checks
        entropy_bits = calculate_entropy(password)
        is_pwned, pwn_count = check_for_breach(password)
        strength_results = check_realistic_strength(password)
        
        # Extract zxcvbn values
        zxcvbn_score = strength_results['score'] # 0 to 4
        
        # 4. CRACK TIME FIX: Use the slow hashing estimate for a conservative, professional result
        crack_time = strength_results['crack_times_display']['offline_slow_hashing_1e4_per_second']
        suggestions = strength_results['feedback']['suggestions']

        # 5. Determine Overall Rating based on a strict hierarchy
        if is_pwned:
            rating = f"COMPROMISED (CRITICAL) - Found {pwn_count:,} times in breaches!"
            
        elif zxcvbn_score == 4:
            rating = "Excellent (Very Strong)"
            
        elif zxcvbn_score >= 3:
            rating = "Good (Strong)"
            
        elif zxcvbn_score >= 2:
            rating = "Fair (Medium)"
            
        else:
            rating = "Poor (Weak)"

        # 6. Output the professional report
        print(f"\n--- Password Analysis Report ---")
        print(f"Password: {'*' * len(password)}")
        print(f"Length: {len(password)}")
        print(f"Overall Rating: {rating}")
        
        print("\n--- Security Metrics ---")
        
        # Realistic Strength Score (zxcvbn)
        print(f"ZXCVBN Score: {zxcvbn_score}/4 (Realistic Strength)")
        
        # Shannon Entropy
        print(f"Shannon Entropy: {entropy_bits} bits")
        
        # Estimated Crack Time (now using the conservative estimate)
        print(f"Estimated Crack Time: {crack_time} (Slow-Hash Offline Attack)")
        
        if suggestions:
            print("\nSuggestions for Improvement:")
            for s in suggestions:
                # Clean suggestion formatting
                print(f" - {s}")
        
        print("-" * 30)

if __name__ == "__main__":
    get_password_input()