"""
Core password checking logic
Author: Prasad
"""

import re
import hashlib
from .entropy import EntropyCalculator
from .patterns import PatternDetector
from .breach_check import BreachChecker
from .dict_check import DictionaryChecker

class PasswordChecker:
    def __init__(self, no_color=False):
        self.no_color = no_color
        self.entropy_calculator = EntropyCalculator()
        self.pattern_detector = PatternDetector()
        self.breach_checker = BreachChecker()
        self.common_passwords = self.load_common_passwords()
        self.dict_checker = DictionaryChecker()
        
    def load_common_passwords(self):
        """Load common passwords from file"""
        common = {
            'password', '123456', '123456789', 'qwerty', 'password123',
            'admin', 'welcome', 'letmein', 'monkey', 'dragon',
            'master', 'football', 'baseball', 'shadow', 'sunshine'
        }
        
        try:
            with open('data/common_passwords.txt', 'r', encoding='utf-8') as f:
                for line in f:
                    word = line.strip().lower()
                    if word:
                        common.add(word)
        except FileNotFoundError:
            pass  # Use built-in list if file doesn't exist
        
        return common
    
    def check(self, password, verbose=False, check_breach=False):
        """Main password checking function"""
        
        if not password or len(password.strip()) == 0:
            print("❌ Error: Password cannot be empty")
            return None
        
        results = {
            'score': 0,
            'strength': '',
            'issues': [],
            'suggestions': [],
            'details': {}
        }
        
        # Length check (max 35 points)
        length_score, length_issues = self.check_length(password)
        results['score'] += length_score
        results['issues'].extend(length_issues)
        results['details']['length'] = len(password)
        
        # Character diversity (max 30 points)
        diversity_score, diversity_issues = self.check_diversity(password)
        results['score'] += diversity_score
        results['issues'].extend(diversity_issues)
        
        # Pattern checks (max 20 points, subtracts for bad patterns)
        pattern_score, pattern_issues = self.pattern_detector.check_all(password)
        results['score'] += pattern_score
        results['issues'].extend(pattern_issues)
        
        # Common password check
        if password.lower() in self.common_passwords:
            results['score'] = max(0, results['score'] - 30)
            results['issues'].append("❌ Password is in top common passwords list")

        # Dictionary word check
        dict_deduction, dict_issues = self.dict_checker.full_check(password)
        results['score'] -= dict_deduction
        results['issues'].extend(dict_issues)
        
        # Calculate entropy
        entropy = self.entropy_calculator.calculate(password)
        results['details']['entropy'] = entropy
        results['details']['crack_time'] = self.estimate_crack_time(entropy)
        results['details']['charset_size'] = self.get_charset_size(password)
        
        # Breach check (API call)
        if check_breach:
            print("🔍 Checking breach databases...")
            is_breached, count = self.breach_checker.check_password(password)
            if is_breached:
                results['score'] = max(0, results['score'] - 40)
                results['issues'].append(f"🚨 Password found in {count:,} data breaches!")
                results['details']['breach_count'] = count
            elif is_breached is None:
                results['issues'].append("⚠️ Could not check breach status (API error)")
        
        # Determine final strength
        results['strength'], results['color'] = self.get_strength(results['score'])
        
        # Generate suggestions
        results['suggestions'] = self.generate_suggestions(results)
        
        # Display results
        self.display_results(results, verbose)
        
        return results
    
    def check_length(self, password):
        """Check password length"""
        length = len(password)
        score = 0
        issues = []
        
        if length < 8:
            score = 0
            issues.append("❌ Too short (< 8 characters) - Easily crackable")
        elif length < 10:
            score = 15
            issues.append("⚠️ Minimum length achieved (8-9 chars)")
        elif length < 12:
            score = 22
            issues.append("✅ Good length (10-11 chars)")
        elif length < 16:
            score = 28
            issues.append("✅✅ Very good length (12-15 chars)")
        else:
            score = 35
            issues.append("🌟🌟 Excellent length (16+ chars)")
        
        return score, issues
    
    def check_diversity(self, password):
        """Check character diversity"""
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))
        
        score = 0
        issues = []
        
        types_used = sum([has_upper, has_lower, has_digit, has_special])
        
        if types_used == 1:
            score = 5
            issues.append("❌ Only one character type - Very weak")
        elif types_used == 2:
            score = 12
            issues.append("⚠️ Only two character types")
        elif types_used == 3:
            score = 22
            issues.append("✅ Good diversity (3 of 4 types)")
        else:
            score = 30
            issues.append("🌟🌟 Excellent diversity (all 4 types)")
        
        # Specific feedback
        if not has_upper:
            issues.append("  └─ Missing uppercase letters (A-Z)")
        if not has_lower:
            issues.append("  └─ Missing lowercase letters (a-z)")
        if not has_digit:
            issues.append("  └─ Missing numbers (0-9)")
        if not has_special:
            issues.append("  └─ Missing special characters (!@#$%^&* etc)")
        
        return score, issues
    
    def get_charset_size(self, password):
        """Calculate character set size used in password"""
        size = 0
        if re.search(r'[a-z]', password):
            size += 26
        if re.search(r'[A-Z]', password):
            size += 26
        if re.search(r'\d', password):
            size += 10
        if re.search(r'[^A-Za-z0-9]', password):
            size += 33  # Common special characters
        return size
    
    def estimate_crack_time(self, entropy):
        """Estimate time to crack password (offline attack)"""
        # Assume 1 billion guesses per second (realistic for modern GPUs)
        guesses_per_second = 1_000_000_000
        guesses = 2 ** entropy
        seconds = guesses / guesses_per_second
        
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.1f} years"
        else:
            return "Centuries (very secure)"
    
    def get_strength(self, score):
        """Determine password strength based on score"""
        if score >= 80:
            return ("VERY STRONG", "🟢")
        elif score >= 65:
            return ("STRONG", "🟢")
        elif score >= 45:
            return ("MODERATE", "🟡")
        elif score >= 25:
            return ("WEAK", "🟠")
        else:
            return ("VERY WEAK", "🔴")
    
    def generate_suggestions(self, results):
        """Generate specific improvement suggestions"""
        suggestions = []
        details = results['details']
        issues = str(results['issues']).lower()
        
        # Length suggestions
        if details['length'] < 12:
            suggestions.append(f"Increase length to 12+ characters (currently {details['length']})")
        
        # Diversity suggestions
        if 'missing uppercase' in issues:
            suggestions.append("Add uppercase letters (A-Z)")
        if 'missing lowercase' in issues:
            suggestions.append("Add lowercase letters (a-z)")
        if 'missing numbers' in issues:
            suggestions.append("Add numbers (0-9)")
        if 'missing special' in issues:
            suggestions.append("Add special characters (!@#$%^&*)")
        
        # Pattern suggestions
        if 'sequential' in issues or 'repeated' in issues:
            suggestions.append("Avoid sequential patterns (abc, 123) and repeated characters")
        
        if 'keyboard' in issues:
            suggestions.append("Avoid keyboard patterns (qwerty, asdfgh)")
        
        # Common password suggestion
        if 'common password' in issues:
            suggestions.append("Avoid common passwords - use random character combinations")
        
        # General entropy suggestion
        if details.get('entropy', 0) < 50:
            suggestions.append("Use completely random characters for maximum security")
        
        if not suggestions:
            suggestions.append("Excellent password! Keep using strong, unique passwords for each account")
        
        return suggestions[:6]
    
    def colorize(self, text, color_code):
        """Add color to text if enabled"""
        if self.no_color:
            return text
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }
        return f"{colors.get(color_code, '')}{text}{colors['reset']}"
    
    def display_results(self, results, verbose):
        """Display formatted results"""
        color = results['color']
        strength = results['strength']
        score = results['score']
        
        # Header
        print(f"\n{self.colorize('='*60, 'cyan')}")
        print(f"{color}Password Strength: {strength} {color}{self.colorize('='*20, 'cyan')}")
        print(f"📊 Score: {score}/100")
        
        if verbose:
            # Detailed metrics
            details = results['details']
            print(f"\n{self.colorize('📈 Detailed Analysis:', 'yellow')}")
            print(f"  • Length: {details['length']} characters")
            print(f"  • Character set size: {details['charset_size']} possible chars")
            print(f"  • Entropy: {details['entropy']:.1f} bits")
            print(f"  • Estimated crack time: {details['crack_time']}")
            
            if 'breach_count' in details:
                print(f"  • Breach appearances: {details['breach_count']:,} times")
            
            # Issues
            if results['issues']:
                print(f"\n{self.colorize('⚠️ Issues Found:', 'yellow')}")
                for issue in results['issues']:
                    print(f"  {issue}")
            
            # Suggestions
            print(f"\n{self.colorize('💡 Suggestions to Improve:', 'green')}")
            for suggestion in results['suggestions']:
                print(f"  • {suggestion}")
        else:
            # Brief mode - only show key issues and suggestions
            critical_issues = [i for i in results['issues'] if '❌' in i or '🚨' in i]
            if critical_issues:
                print(f"\n{self.colorize('⚠️ Critical Issues:', 'red')}")
                for issue in critical_issues[:3]:
                    print(f"  {issue}")
            
            print(f"\n{self.colorize('💡 Top Suggestion:', 'green')}")
            print(f"  • {results['suggestions'][0]}")
        
        print(self.colorize('='*60, 'cyan'))
