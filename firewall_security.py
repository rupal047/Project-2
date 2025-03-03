import re
# Define a function to check for security issues in submitted data
def security_scan(input_data, firewall_enabled=True):
    # Check if firewall is disabled
    if not firewall_enabled:
        print('Firewall is disabled. Skipping security scan.')
        return True  # Placeholder value, replace with actual result

    # Look for HTML script tags/cross-site scripting attacks
    # Vulnerability Title - Cross Site Scripting (XSS)
    if re.search("(\<(script)\>)", input_data):
        return False

    # Check for common SQL injection attacks
    # Vulnerability Title - SQL injection
    if re.search("((\%27)|(\')|(\-\-)|(\%23))[^\n]*((\%27)|(\')|(\-\-)|(\%23))", input_data):
        return False
    
    # Look for sensitive data being transmitted or stored in an unencrypted format
    # Vulnerability Title - Default Credentials/Sensitive Data
    elif re.search(r'\b(password|123456|qwerty|abc123|letmein|monkey|football|iloveyou|admin|welcome|login|princess|sunshine|flower|hottie|loveme|zaq1zaq1|baseball|dragon|superman)\b', input_data, re.IGNORECASE):
        return False
        
    # Look for various potential attacks using special characters
    # Vulnerability Title - Improper Input Validation
    elif re.search("';'", input_data):
        return False
    elif re.search('";"', input_data):
        return False
    elif re.search("((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", input_data):
        return False
    elif re.search("--", input_data):
        return False
    elif re.search("\*", input_data):
        return False
    elif re.search("\|", input_data):
        return False
    elif re.search("[^\w\s]", input_data):
        return False

    # If no potential security issues are found, return True
    else:
        return True

def check_default_credentials(username, password):
    # Implement your logic to check default credentials
    # For example, check if the provided username and password match some predefined values
    if username == "root" and password == "root":
        return True
    else:
        return False


        