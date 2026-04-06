"""
Password entropy calculation module
Author: Prasad
"""

import math
import re

class EntropyCalculator:
    def __init__(self):
        pass
    
    def calculate(self, password):
        """
        Calculate the entropy of a password in bits.
        Entropy = log2(character_set_size ^ password_length)
        """
        if not password:
            return 0
        
        charset_size = self.get_charset_size(password)
        password_length = len(password)
        
        # Entropy formula: log2(R^L) = L * log2(R)
        if charset_size > 1:
            entropy = password_length * math.log2(charset_size)
        else:
            entropy = 0
        
        return round(entropy, 2)
    
    def get_charset_size(self, password):
        """
        Determine the size of the character set used in the password
        """
        charset_size = 0
        
        # Lowercase letters
        if re.search(r'[a-z]', password):
            charset_size += 26
        
        # Uppercase letters
        if re.search(r'[A-Z]', password):
            charset_size += 26
        
        # Digits
        if re.search(r'\d', password):
            charset_size += 10
        
        # Special characters
        if re.search(r'[^A-Za-z0-9]', password):
            charset_size += 33  # Common special characters (!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)
        
        return charset_size
    
    def get_entropy_rating(self, entropy):
        """
        Rate the entropy strength
        """
        if entropy < 30:
            return "Very Weak", "🔴"
        elif entropy < 50:
            return "Weak", "🟠"
        elif entropy < 70:
            return "Moderate", "🟡"
        elif entropy < 90:
            return "Strong", "🟢"
        else:
            return "Very Strong", "🟢"
    
    def calculate_bits_per_character(self, password):
        """
        Calculate average bits per character
        """
        entropy = self.calculate(password)
        length = len(password)
        
        if length > 0:
            return round(entropy / length, 2)
        return 0
