"""
Password Strength Detector - Advanced password security analysis tool
Author: Prasad
"""

from .checker import PasswordChecker
from .generator import PasswordGenerator
from .entropy import EntropyCalculator
from .patterns import PatternDetector
from .breach_check import BreachChecker

__version__ = "1.0.0"
__author__ = "Prasad"
__all__ = [
    'PasswordChecker',
    'PasswordGenerator', 
    'EntropyCalculator',
    'PatternDetector',
    'BreachChecker'
]
