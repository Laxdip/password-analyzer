"""
Advanced Password Strength Detector
Author: Prasad
"""

import argparse
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from password_strength.checker import PasswordChecker
from password_strength.generator import PasswordGenerator

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Password Strength Detector - Check, analyze, and generate secure passwords',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Check a password
  python run.py "MyP@ssw0rd123"
  
  # Interactive mode (check multiple passwords)
  python run.py --interactive
  
  # Generate a strong password
  python run.py --generate
  
  # Generate with custom length
  python run.py --generate --length 20
  
  # Check if password has been in data breaches
  python run.py "password123" --check-breach
  
  # Verbose output with detailed analysis
  python run.py "qwerty123" --verbose
        '''
    )
    
    parser.add_argument('password', nargs='?', help='Password to check (optional in interactive/generate mode)')
    parser.add_argument('--interactive', '-i', action='store_true', 
                       help='Interactive mode - check multiple passwords')
    parser.add_argument('--generate', '-g', action='store_true',
                       help='Generate a strong random password')
    parser.add_argument('--length', '-l', type=int, default=16,
                       help='Password length for generation (default: 16, min: 8, max: 64)')
    parser.add_argument('--check-breach', '-b', action='store_true',
                       help='Check if password has appeared in data breaches (uses HIBP API)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed analysis')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    # Validate length for generation
    if args.length < 8:
        print("❌ Error: Minimum password length is 8 characters")
        sys.exit(1)
    if args.length > 64:
        print("❌ Error: Maximum password length is 64 characters")
        sys.exit(1)
    
    # Handle generate mode
    if args.generate:
        generator = PasswordGenerator()
        password = generator.generate(length=args.length)
        print(f"\n🔐 Generated Password: {password}\n")
        print("─" * 60)
        # Automatically analyze the generated password
        checker = PasswordChecker(no_color=args.no_color)
        checker.check(password, verbose=args.verbose, check_breach=args.check_breach)
        
    # Handle interactive mode
    elif args.interactive:
        interactive_mode(no_color=args.no_color, check_breach=args.check_breach, verbose=args.verbose)
        
    # Handle single password check
    elif args.password:
        checker = PasswordChecker(no_color=args.no_color)
        result = checker.check(
            args.password, 
            verbose=args.verbose, 
            check_breach=args.check_breach
        )
        
    # No arguments - show help
    else:
        parser.print_help()

def interactive_mode(no_color=False, check_breach=False, verbose=False):
    """Interactive password checking mode"""
    print("\n" + "="*60)
    print("🔐 Advanced Password Strength Detector - Interactive Mode")
    print("="*60)
    print("Type 'quit' or 'exit' to quit")
    print("Type 'generate' to create a strong password")
    print("─" * 60)
    
    checker = PasswordChecker(no_color=no_color)
    generator = PasswordGenerator()
    
    while True:
        print()
        password = input("Enter password to check: ").strip()
        
        if password.lower() in ['quit', 'exit']:
            print("\n👋 Goodbye! Stay secure!")
            break
        
        if password.lower() == 'generate':
            pwd = generator.generate()
            print(f"\n💡 Generated password: {pwd}")
            print("─" * 60)
            checker.check(pwd, verbose=verbose, check_breach=check_breach)
            continue
        
        if not password:
            print("⚠️ Please enter a password")
            continue
        
        print("─" * 60)
        checker.check(password, verbose=verbose, check_breach=check_breach)

if __name__ == "__main__":
    main()
