// --- Global Elements ---
const passwordInput = document.getElementById('password-input');
const strengthMeter = document.getElementById('strength-meter');
const ratingOutput = document.getElementById('rating-output');
const breachOutput = document.getElementById('breach-output');
const scoreOutput = document.getElementById('score-output');
const crackTimeOutput = document.getElementById('crack-time-output');
const entropyOutput = document.getElementById('entropy-output');
const suggestionsOutput = document.getElementById('suggestions-output');
const showPasswordToggle = document.getElementById('show-password-toggle');

// Define color and class mappings for the strength score
const scoreColors = ['#dc3545', '#fd7e14', '#ffc107', '#198754', '#0d6efd']; // Red, Orange, Yellow, Green, Blue
const scoreClasses = ['weak', 'fair', 'medium', 'good', 'excellent'];
const scoreText = ['Poor (Weak)', 'Fair (Medium)', 'Good (Strong)', 'Excellent (Very Strong)', 'Excellent (Very Strong)'];

// --- Hashing Function (for HIBP k-anonymity) ---
// Uses the browser's Web Crypto API for secure SHA-1 hashing.
async function sha1(str) {
    // Ensure str is treated as a string, important for API integrity
    const buffer = new TextEncoder("utf-8").encode(String(str)); 
    const hash = await crypto.subtle.digest("SHA-1", buffer);
    
    // Convert hash buffer to hex string (same as Python's hexdigest().upper())
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
}

// --- 1. HIBP Breach Check (k-anonymity with Exponential Backoff) ---
async function checkBreachStatus(password) {
    if (password.length === 0) {
        // Reset state for empty password
        breachOutput.textContent = 'N/A';
        breachOutput.className = 'awaiting';
        return { isPwned: false, count: 0 };
    }
    
    // Hash the password and get the prefix/suffix
    const sha1Password = await sha1(password);
    const prefix = sha1Password.substring(0, 5);
    const suffix = sha1Password.substring(5);
    
    // Set status to checking
    breachOutput.textContent = 'Checking...';
    breachOutput.className = 'checking';
    
    const apiUrl = `https://api.pwnedpasswords.com/range/${prefix}`;
    
    const maxRetries = 5;
    let delay = 1000; // 1 second initial delay

    for (let i = 0; i < maxRetries; i++) {
        try {
            const response = await fetch(apiUrl);

            if (response.status === 429) {
                // Too Many Requests - Implement exponential backoff
                const retryAfter = response.headers.get('Retry-After');
                const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : delay;
                
                console.warn(`Rate limit hit. Retrying in ${waitTime}ms...`);
                await new Promise(resolve => setTimeout(resolve, waitTime));
                delay *= 2; // Exponential increase
                continue; // Retry the request
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const text = await response.text();
            
            let count = 0;
            const lines = text.split('\n');

            // Search for the suffix and count
            for (const line of lines) {
                const [hashSuffix, pwnCount] = line.split(':');
                if (hashSuffix === suffix) {
                    count = parseInt(pwnCount);
                    break;
                }
            }

            // Update UI based on results
            if (count > 0) {
                breachOutput.textContent = `${count.toLocaleString()} times`; // Show count
                breachOutput.className = 'compromised';
                return { isPwned: true, count: count };
            } else {
                breachOutput.textContent = 'Not Found (Safe)';
                breachOutput.className = 'not-found';
                return { isPwned: false, count: 0 };
            }

        } catch (error) {
            console.error('Breach check failed:', error);
            breachOutput.textContent = 'API Error';
            breachOutput.className = 'awaiting';
            return { isPwned: false, count: 0 };
        }
    }

    // If loop finishes without success
    breachOutput.textContent = 'Check Failed (Timeout)';
    breachOutput.className = 'awaiting';
    return { isPwned: false, count: 0 };
}

// --- 2. Shannon Entropy Calculation ---
function calculateEntropy(password) {
    if (password.length === 0) return 0;

    let R = 0; // Pool size (size of the character set)
    
    // Check for character sets (case-insensitive for a more accurate R calculation)
    if (/[a-z]/.test(password)) R += 26; // Lowercase letters
    if (/[A-Z]/.test(password)) R += 26; // Uppercase letters
    if (/[0-9]/.test(password)) R += 10; // Digits
    // A broader set of special characters (~33 is a common conservative estimate)
    if (/[^a-zA-Z0-9\s]/.test(password)) R += 33; 
    
    if (R === 0) return 0;
    
    const L = password.length;
    // Entropy (bits) = L * log2(R)
    const entropy = L * (Math.log(R) / Math.log(2)); 
    
    return entropy.toFixed(2);
}

// --- 3. Main Analysis and UI Update ---
async function analyzePassword() {
    const password = passwordInput.value;
    
    // --- CRITICAL FIX: Handle Empty Password State ---
    if (password.length === 0) {
        // Set the rating output to match the requested 'Awaiting Input' text.
        ratingOutput.innerHTML = `<span class="awaiting">Awaiting Input</span>`; 
        scoreOutput.textContent = 'N/A';
        crackTimeOutput.textContent = 'N/A';
        entropyOutput.textContent = 'N/A';
        suggestionsOutput.innerHTML = '';

        // Reset strength bar to 0% and default color
        strengthMeter.style.backgroundColor = '#e0e0e0';
        strengthMeter.style.width = '0%';

        // Reset breach status via dedicated function call (synchronous empty check)
        checkBreachStatus(password); 
        return;
    }
    
    // 1. ZXCZBN Check
    // Note: zxcvbn is a global function loaded from the CDN
    const zxcvbnResult = zxcvbn(password);
    const zxcvbnScore = zxcvbnResult.score; // 0 to 4
    const entropyBits = calculateEntropy(password);

    // 2. HIBP Check (runs asynchronously)
    const breachStatus = await checkBreachStatus(password);
    const isPwned = breachStatus.isPwned;
    const pwnCount = breachStatus.count;

    let ratingText;
    let ratingClass;

    // 3. Determine Overall Security Rating based on strict hierarchy
    if (isPwned) {
        // If compromised, it is CRITICAL regardless of zxcvbn score
        ratingText = `CRITICAL (COMPROMISED - ${pwnCount.toLocaleString()} times!)`;
        ratingClass = 'weak'; // Visually flag as weakest security class
    } else {
        // Use zxcvbn score for general strength if not compromised
        ratingText = scoreText[zxcvbnScore];
        // Set class based on score for coloring the output text
        ratingClass = scoreClasses[zxcvbnScore];
    }

    // --- Update UI Metrics ---
    ratingOutput.innerHTML = `<span class="${ratingClass}">${ratingText}</span>`; 
    scoreOutput.textContent = `${zxcvbnScore}/4`;
    entropyOutput.textContent = `${entropyBits} bits`;
    
    // Use the conservative 'offline_slow_hashing' estimate for Crack Time
    crackTimeOutput.textContent = zxcvbnResult.crack_times_display['offline_slow_hashing_1e4_per_second'];
    
    // --- Update Strength Bar and Suggestions ---
    strengthMeter.style.backgroundColor = scoreColors[zxcvbnScore]; 
    // Map score 0-4 to 0-100% width
    strengthMeter.style.width = `${(zxcvbnScore / 4) * 100}%`; 

    if (zxcvbnResult.feedback.suggestions && zxcvbnResult.feedback.suggestions.length > 0) {
        let suggestionsHTML = '<h3 style="margin-top: 15px;">Suggestions for Improvement:</h3><ul>';
        zxcvbnResult.feedback.suggestions.forEach(suggestion => {
            suggestionsHTML += `<li>${suggestion}</li>`;
        });
        suggestionsHTML += '</ul>';
        suggestionsOutput.innerHTML = suggestionsHTML;
    } else {
        suggestionsOutput.innerHTML = '';
    }
}

// --- Password Visibility Toggle ---
function togglePasswordVisibility() {
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        showPasswordToggle.textContent = "Hide Password";
    } else {
        passwordInput.type = "password";
        showPasswordToggle.textContent = "Show Password";
    }
}

// Add event listener for real-time analysis
passwordInput.addEventListener('input', analyzePassword);

// Add event listener for the visibility toggle
showPasswordToggle.addEventListener('click', togglePasswordVisibility);

// Initial call to set the UI to the 'Awaiting Input' state immediately on load
window.onload = analyzePassword;