"""Shared fixtures: put the repo root on sys.path so tests import the scripts."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
