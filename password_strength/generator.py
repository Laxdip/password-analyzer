"""
Secure password generator
Author: Prasad
"""

import secrets
import random
import string

class PasswordGenerator:
    def __init__(self):
        # Character sets
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
    def generate(self, length=16, use_upper=True, use_lower=True, 
                 use_digits=True, use_symbols=True):
        """
        Generate a cryptographically secure random password
        
        Args:
            length: Password length (8-64)
            use_upper: Include uppercase letters
            use_lower: Include lowercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            
        Returns:
            Secure random password string
        """
        # Validate length
        if length < 8:
            length = 8
        if length > 64:
            length = 64
        
        # Build character pool
        char_pool = ""
        if use_lower:
            char_pool += self.lowercase
        if use_upper:
            char_pool += self.uppercase
        if use_digits:
            char_pool += self.digits
        if use_symbols:
            char_pool += self.symbols
        
        # Ensure at least one character type is selected
        if not char_pool:
            char_pool = self.lowercase + self.digits
        
        # Generate password using secrets module (cryptographically secure)
        password = []
        
        # Ensure at least one character from each selected type
        if use_lower:
            password.append(secrets.choice(self.lowercase))
        if use_upper:
            password.append(secrets.choice(self.uppercase))
        if use_digits:
            password.append(secrets.choice(self.digits))
        if use_symbols:
            password.append(secrets.choice(self.symbols))
        
        # Fill the rest randomly
        remaining_length = length - len(password)
        for _ in range(remaining_length):
            password.append(secrets.choice(char_pool))
        
        # Shuffle to avoid predictable pattern
        random.shuffle(password)
        
        return ''.join(password)
    
    def generate_memorable(self, words=3, separator="-", add_digits=True):
        """
        Generate a memorable password using random words
        
        Args:
            words: Number of words (2-6)
            separator: Character between words
            add_digits: Add random digits at end
            
        Returns:
            Memorable password string
        """
        common_words = [
            'tiger', 'eagle', 'ocean', 'mountain', 'forest', 'river',
            'cloud', 'storm', 'thunder', 'lightning', 'galaxy', 'star',
            'phoenix', 'dragon', 'falcon', 'wolf', 'raven', 'shadow',
            'crystal', 'silver', 'golden', 'brave', 'swift', 'bright'
        ]
        
        word_list = []
        for _ in range(min(words, 6)):
            word_list.append(secrets.choice(common_words))
        
        password = separator.join(word_list)
        
        if add_digits:
            password += secrets.choice(self.digits)
            password += secrets.choice(self.digits)
        
        return password
