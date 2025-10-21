Hashia: Cryptographic Integrity Check 

Real-Time Security Audit & Threat Intelligence

Hashia is a modern, single-page web application designed to provide a comprehensive multi-layered security audit of potential passwords. It moves beyond basic strength scores by integrating cryptographic analysis and global threat intelligence.

The system performs three critical checks in real-time, ensuring client-side verification so the plain text password never leaves your browser:

Strength Score (zxcvbn): Assesses the password's resistance to modern cracking methods.

Breach Status (HIBP k-anonymity): Checks the password against known compromised passwords from data breaches.

Entropy (bits): Provides a mathematical measure of the password's true cryptographic randomness.

Prerequisites

This project is a pure frontend web application and requires only a modern web browser to run.

The application leverages the following key external libraries:

Tailwind CSS: For utility-first styling and responsive design.

zxcvbn Library: For realistic password strength scoring.

Have I Been Pwned (HIBP) API: Used securely for breach checking.


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
