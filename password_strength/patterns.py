"""
Pattern detection for weak password patterns
Author: Prasad
"""

import re

class PatternDetector:
    def __init__(self):
        # Common keyboard patterns
        self.keyboard_rows = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            'QWERTYUIOP', 'ASDFGHJKL', 'ZXCVBNM'
        ]
        
        # Common sequences
        self.sequences = [
            '1234567890', '9876543210',
            'abcdefghijklmnopqrstuvwxyz',
            'zyxwvutsrqponmlkjihgfedcba'
        ]
    
    def check_all(self, password):
        """
        Check password for all patterns
        Returns: (score, list_of_issues)
        """
        score = 20  # Start with full points, subtract for issues
        issues = []
        
        # Check for sequential patterns
        seq_score, seq_issues = self.check_sequential(password)
        score -= seq_score
        issues.extend(seq_issues)
        
        # Check for repeated characters
        repeat_score, repeat_issues = self.check_repeated_chars(password)
        score -= repeat_score
        issues.extend(repeat_issues)
        
        # Check for keyboard patterns
        keyboard_score, keyboard_issues = self.check_keyboard_patterns(password)
        score -= keyboard_score
        issues.extend(keyboard_issues)
        
        # Check for common substitutions
        sub_score, sub_issues = self.check_common_substitutions(password)
        score -= sub_score
        issues.extend(sub_issues)
        
        # Check for dates
        date_score, date_issues = self.check_dates(password)
        score -= date_score
        issues.extend(date_issues)
        
        # Ensure score doesn't go negative
        score = max(0, score)
        
        return score, issues
    
    def check_sequential(self, password):
        """
        Check for sequential characters (abc, 123)
        """
        password_lower = password.lower()
        score = 0
        issues = []
        
        for seq in self.sequences:
            for i in range(len(seq) - 2):
                pattern = seq[i:i+3]
                if pattern in password_lower:
                    score += 5
                    issues.append(f"❌ Contains sequential pattern '{pattern}'")
                    break
        
        # Check for reverse sequences
        for seq in self.sequences:
            rev_seq = seq[::-1]
            for i in range(len(rev_seq) - 2):
                pattern = rev_seq[i:i+3]
                if pattern in password_lower:
                    score += 5
                    issues.append(f"❌ Contains reverse sequential pattern '{pattern}'")
                    break
        
        return min(score, 15), issues[:2]  # Max 15 points deduction, max 2 issues
    
    def check_repeated_chars(self, password):
        """
        Check for repeated characters (aaa, 111, etc)
        """
        score = 0
        issues = []
        
        # Check for 3+ repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                score += 4
                issues.append(f"❌ Repeated character '{password[i]}' appears 3+ times")
                break
        
        # Check for 2 repeated characters multiple times
        repeat_count = 0
        for i in range(len(password) - 1):
            if password[i] == password[i+1]:
                repeat_count += 1
        
        if repeat_count >= 2:
            score += 3
            issues.append(f"❌ Multiple repeated character pairs")
        
        return min(score, 10), issues[:2]
    
    def check_keyboard_patterns(self, password):
        """
        Check for keyboard patterns (qwerty, asdfgh)
        """
        password_lower = password.lower()
        score = 0
        issues = []
        
        for row in self.keyboard_rows:
            # Check for 4+ consecutive keys on same keyboard row
            for i in range(len(row) - 3):
                pattern = row[i:i+4]
                if pattern in password_lower:
                    score += 6
                    issues.append(f"❌ Keyboard pattern '{pattern}' detected")
                    break
            
            # Check for adjacent keys
            for i in range(len(row) - 1):
                pattern = row[i:i+2]
                if pattern in password_lower:
                    score += 2
        
        return min(score, 12), issues[:2]
    
    def check_common_substitutions(self, password):
        """
        Check for common letter substitutions ( @ for a, 3 for e, etc)
        """
        password_lower = password.lower()
        score = 0
        issues = []
        
        substitutions = {
            '@': 'a', '4': 'a',
            '3': 'e', 
            '1': 'i', '!': 'i',
            '0': 'o',
            '5': 's', '$': 's',
            '7': 't',
            '8': 'b'
        }
        
        # Check if substitutions are used with common words
        common_words = ['password', 'admin', 'welcome', 'letmein', 'master']
        
        for sub_char, original in substitutions.items():
            if sub_char in password:
                # Create substituted version
                test_pwd = password_lower.replace(sub_char, original)
                for word in common_words:
                    if word in test_pwd:
                        score += 4
                        issues.append(f"❌ Common word '{word}' with character substitution")
                        break
        
        return min(score, 10), issues[:2]
    
    def check_dates(self, password):
        """
        Check for date patterns (DDMMYYYY, MMDDYYYY, etc)
        """
        score = 0
        issues = []
        
        # Look for 6-8 digit sequences that could be dates
        date_patterns = re.findall(r'\d{6,8}', password)
        
        for pattern in date_patterns:
            # Check for DDMMYYYY (8 digits)
            if len(pattern) == 8:
                day = int(pattern[0:2])
                month = int(pattern[2:4])
                year = int(pattern[4:8])
                
                if 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2030:
                    score += 5
                    issues.append(f"❌ Contains date pattern '{pattern}' (DDMMYYYY)")
                    break
                
                # Check for MMDDYYYY
                month = int(pattern[0:2])
                day = int(pattern[2:4])
                year = int(pattern[4:8])
                
                if 1 <= month <= 12 and 1 <= day <= 31 and 1900 <= year <= 2030:
                    score += 5
                    issues.append(f"❌ Contains date pattern '{pattern}' (MMDDYYYY)")
                    break
            
            # Check for YYYYMMDD (8 digits)
            if len(pattern) == 8:
                year = int(pattern[0:4])
                month = int(pattern[4:6])
                day = int(pattern[6:8])
                
                if 1900 <= year <= 2030 and 1 <= month <= 12 and 1 <= day <= 31:
                    score += 5
                    issues.append(f"❌ Contains date pattern '{pattern}' (YYYYMMDD)")
                    break
        
        return min(score, 10), issues[:1]
