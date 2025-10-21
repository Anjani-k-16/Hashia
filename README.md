# SecurePass-Checker: A Multi-Layered Password Analysis Tool

## Project Summary
This Python-based tool analyzes password strength by employing **three distinct security metrics**:
1. **Complexity Scoring:** Numerical score based on length and character set variety (upper/lower/digits/special).
2. **Shannon Entropy Calculation:** A mathematical measure (in bits) of the password's randomness and attack difficulty.
3. **Breach Lookup:** Integration with the **Have I Been Pwned (HIBP) API** using **k-anonymity** to check if the password has appeared in any public data breach.

## Core Security Features (For Resume Highlight)
* **Threat Intelligence Integration:** Prioritizes breach status over complexity. A password is automatically flagged as **COMPROMISED** if it is found in the HIBP database.
* **Cryptographic Principles:** Demonstrates understanding of entropy, a fundamental concept in data security and cryptography.
* **Privacy-Preserving API Usage:** Utilizes the k-anonymity model (only sending the first 5 characters of the SHA-1 hash) to protect user input during the breach check.

## Setup and Running the Project

### Prerequisites
* Python 3.x
* The `requests` library for API access.

### Installation
1.  Clone this repository or download the files.
2.  Navigate to the project directory.
3.  Install the required library:
    ```bash
    pip install -r requirements.txt
    ```

### Execution
Run the script from your terminal:
```bash
python password_checker.py