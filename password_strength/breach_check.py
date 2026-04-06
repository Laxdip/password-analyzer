"""
Have I Been Pwned API integration for breach checking
Author: Prasad
"""

import hashlib
import requests
import sys

class BreachChecker:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.api_url = "https://api.pwnedpasswords.com/range/"
        
    def check_password(self, password):
        """
        Check if password has been in data breaches
        Returns: (is_breached, breach_count)
        """
        if not password:
            return False, 0
        
        try:
            # Create SHA-1 hash of password
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP API
            url = f"{self.api_url}{prefix}"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                # Check if our suffix exists in response
                for line in response.text.splitlines():
                    line_suffix, count = line.split(':')
                    if line_suffix == suffix:
                        return True, int(count)
                return False, 0
            else:
                return None, 0
                
        except requests.exceptions.Timeout:
            print("⚠️ API timeout - breach check skipped")
            return None, 0
        except requests.exceptions.RequestException as e:
            print(f"⚠️ API error: {str(e)[:50]} - breach check skipped")
            return None, 0
        except Exception as e:
            print(f"⚠️ Unexpected error: {str(e)[:50]} - breach check skipped")
            return None, 0
