"""
Dictionary attack simulation and common word checking
Author: Prasad
"""

import re
from pathlib import Path

class DictionaryChecker:
    def __init__(self):
        self.common_words = self.load_wordlist()
        self.common_patterns = [
            r'password', r'admin', r'welcome', r'login', r'user',
            r'qwerty', r'abc123', r'letmein', r'monkey', r'dragon',
            r'master', r'sunshine', r'football', r'baseball', r'shadow'
        ]
    
    def load_wordlist(self):
        """Load dictionary wordlist"""
        words = set()
        
        # Common words to always check
        base_words = {
            'password', 'admin', 'welcome', 'login', 'user', 'guest',
            'qwerty', 'abc123', 'letmein', 'monkey', 'dragon', 'master',
            'sunshine', 'football', 'baseball', 'shadow', 'superman',
            'batman', 'spiderman', 'starwars', 'matrix', 'hunter',
            'trustno1', 'access', 'secret', 'private', 'temp', 'default'
        }
        words.update(base_words)
        
        # Try to load additional words from file
        try:
            dict_path = Path(__file__).parent.parent / 'data' / 'common_passwords.txt'
            if dict_path.exists():
                with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip().lower()
                        if word and len(word) >= 4:
                            words.add(word)
        except Exception:
            pass  # Use base words if file not found
        
        return words
    
    def check_dictionary(self, password):
        """
        Check if password contains dictionary words
        Returns: (score_deduction, list_of_issues)
        """
        password_lower = password.lower()
        score_deduction = 0
        issues = []
        
        # Check for exact matches
        if password_lower in self.common_words:
            score_deduction += 25
            issues.append(f"❌ Password is a common dictionary word")
            return score_deduction, issues
        
        # Check for words with common substitutions
        substituted = self.apply_common_substitutions(password_lower)
        if substituted in self.common_words:
            score_deduction += 20
            issues.append(f"❌ Password uses common word with character substitutions")
            return score_deduction, issues
        
        # Check for words embedded in password
        for word in self.common_words:
            if len(word) >= 4 and word in password_lower:
                score_deduction += 10
                issues.append(f"❌ Contains dictionary word '{word}'")
                if score_deduction >= 20:  # Limit deduction
                    break
        
        # Check for repeated dictionary words
        for word in self.common_words:
            if len(word) >= 3 and password_lower.count(word) > 1:
                score_deduction += 15
                issues.append(f"❌ Contains repeated word '{word}'")
                break
        
        return min(score_deduction, 30), issues[:3]
    
    def apply_common_substitutions(self, password):
        """Apply common leet speak substitutions"""
        substitutions = {
            '4': 'a', '@': 'a',
            '3': 'e',
            '1': 'i', '!': 'i',
            '0': 'o',
            '5': 's', '$': 's',
            '7': 't',
            '8': 'b'
        }
        
        result = password
        for leet, original in substitutions.items():
            result = result.replace(leet, original)
        
        return result
    
    def check_pattern_based(self, password):
        """
        Check for pattern-based dictionary attacks
        Like: password123, admin2024, welcome!
        """
        password_lower = password.lower()
        score_deduction = 0
        issues = []
        
        # Check for word + number patterns
        for word in list(self.common_words)[:100]:  # Check top 100
            if len(word) >= 4:
                # Word followed by numbers
                if re.search(rf'{word}\d+', password_lower):
                    score_deduction += 15
                    issues.append(f"❌ Dictionary word '{word}' followed by numbers")
                    break
                
                # Word preceded by numbers
                if re.search(rf'\d+{word}', password_lower):
                    score_deduction += 15
                    issues.append(f"❌ Numbers followed by dictionary word '{word}'")
                    break
                
                # Word with special chars
                if re.search(rf'{word}[!@#$%^&*]', password_lower):
                    score_deduction += 10
                    issues.append(f"❌ Dictionary word '{word}' with special character")
                    break
        
        # Check for year patterns (word + year)
        for word in list(self.common_words)[:100]:
            for year in range(2020, 2030):
                if f"{word}{year}" in password_lower or f"{year}{word}" in password_lower:
                    score_deduction += 12
                    issues.append(f"❌ Dictionary word '{word}' with year {year}")
                    break
        
        return min(score_deduction, 25), issues[:2]
    
    def full_check(self, password):
        """
        Complete dictionary check
        Returns: (total_score_deduction, all_issues)
        """
        total_deduction = 0
        all_issues = []
        
        # Basic dictionary check
        deduction1, issues1 = self.check_dictionary(password)
        total_deduction += deduction1
        all_issues.extend(issues1)
        
        # Pattern-based check
        deduction2, issues2 = self.check_pattern_based(password)
        total_deduction += deduction2
        all_issues.extend(issues2)
        
        return min(total_deduction, 40), all_issues[:4]
