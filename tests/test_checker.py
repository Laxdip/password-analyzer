"""
Basic tests for password strength checker
Author: Prasad
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from password_strength.checker import PasswordChecker
from password_strength.generator import PasswordGenerator
from password_strength.entropy import EntropyCalculator

def test_weak_passwords():
    """Test that weak passwords get low scores"""
    checker = PasswordChecker(no_color=True)
    
    weak_passwords = [
        "password",
        "123456",
        "qwerty",
        "abc123",
        "password123"
    ]
    
    for pwd in weak_passwords:
        result = checker.check(pwd, verbose=False, check_breach=False)
        assert result['score'] < 40, f"Password '{pwd}' should be weak but got {result['score']}"
        print(f"✅ '{pwd}' correctly identified as weak ({result['score']}/100)")
    
    return True

def test_strong_passwords():
    """Test that strong passwords get high scores"""
    checker = PasswordChecker(no_color=True)
    generator = PasswordGenerator()
    
    strong_pwd = generator.generate(length=16)
    result = checker.check(strong_pwd, verbose=False, check_breach=False)
    
    assert result['score'] > 70, f"Generated password should be strong but got {result['score']}/100"
    print(f"✅ Generated strong password scored {result['score']}/100")
    
    return True

def test_entropy_calculation():
    """Test entropy calculator"""
    calculator = EntropyCalculator()
    
    # Simple password should have low entropy
    low_entropy = calculator.calculate("password")
    
    # Complex password should have high entropy
    high_entropy = calculator.calculate("MyC0mpl3x!P@ssw0rd#2024")
    
    assert low_entropy < high_entropy, "Complex password should have higher entropy"
    print(f"✅ Entropy calculation works (simple: {low_entropy}, complex: {high_entropy})")
    
    return True

def test_password_generator():
    """Test password generator"""
    generator = PasswordGenerator()
    
    # Test length
    pwd = generator.generate(length=20)
    assert len(pwd) == 20, f"Password length should be 20, got {len(pwd)}"
    
    # Test character types
    pwd = generator.generate(use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    
    assert has_upper and has_lower and has_digit, "Password missing required character types"
    print(f"✅ Password generator works (example: {pwd[:10]}...)")
    
    return True

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("Running Password Strength Detector Tests")
    print("="*60 + "\n")
    
    tests = [
        ("Weak Password Detection", test_weak_passwords),
        ("Strong Password Detection", test_strong_passwords),
        ("Entropy Calculation", test_entropy_calculation),
        ("Password Generator", test_password_generator)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"❌ {test_name} failed: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
