#!/usr/bin/env python3
"""
Enum4linux Tool Wrapper for Guardian CLI Deluxe
Ensures null session is used by default without password prompts
"""

import subprocess
import sys
import argparse
from typing import List, Optional


class Enum4linuxWrapper:
    """Wrapper for enum4linux to enforce null session by default"""
    
    def __init__(self, use_ng: bool = False):
        # Try to find the correct binary (prefer enum4linux-ng over enum4linux-ng.py)
        if use_ng:
            import shutil
            self.command = shutil.which("enum4linux-ng") or shutil.which("enum4linux-ng.py") or "enum4linux-ng"
        else:
            self.command = "enum4linux"
        self.use_ng = use_ng
    
    def run_null_session(self, target: str, options: Optional[List[str]] = None) -> int:
        """
        Run enum4linux with null session (no credentials)
        
        Args:
            target: Target IP or hostname
            options: Additional command line options
            
        Returns:
            Return code from enum4linux
        """
        # Build command - CRITICAL: No -u or -p flags for null session
        cmd = [self.command]
        
        # Add default enumeration option
        if self.use_ng:
            cmd.append("-A")  # All enumeration for ng version
        else:
            cmd.append("-a")  # All simple enumeration for classic version
        
        # Add any additional options
        if options:
            cmd.extend(options)
        
        # Add target last
        cmd.append(target)
        
        print(f"[+] Running enum4linux null session check: {' '.join(cmd)}")
        print("[+] Note: Using null session (no credentials)")
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Print output
            if result.stdout:
                print(result.stdout)
            
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            # Check for null session success/failure
            self._check_null_session_result(result.stdout)
            
            return result.returncode
            
        except subprocess.TimeoutExpired:
            print("[!] Error: enum4linux timed out after 5 minutes", file=sys.stderr)
            return 124
        except FileNotFoundError:
            print(f"[!] Error: {self.command} not found. Please install enum4linux.", file=sys.stderr)
            return 127
        except Exception as e:
            print(f"[!] Error running enum4linux: {e}", file=sys.stderr)
            return 1
    
    def _check_null_session_result(self, output: str):
        """Check if null session was successful"""
        if "Session Check" in output:
            if "allows sessions using username '', password ''" in output:
                print("\n[+] SUCCESS: Null session is allowed!")
            elif "Server doesn't allow session using username '', password ''" in output:
                print("\n[-] Null session is NOT allowed on this target")
            else:
                print("\n[?] Null session check result unclear")


def main():
    parser = argparse.ArgumentParser(
        description="Enum4linux wrapper for null session testing"
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )
    parser.add_argument(
        "--ng",
        action="store_true",
        help="Use enum4linux-ng instead of classic enum4linux"
    )
    parser.add_argument(
        "--shares-only",
        action="store_true",
        help="Only enumerate shares"
    )
    parser.add_argument(
        "--users-only",
        action="store_true",
        help="Only enumerate users"
    )
    parser.add_argument(
        "--output",
        help="Output file path (for enum4linux-ng YAML/JSON)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Build options list
    options = []
    
    if args.shares_only:
        options.append("-S")
    
    if args.users_only:
        options.append("-U")
    
    if args.verbose:
        options.append("-v")
    
    if args.output and args.ng:
        if args.output.endswith('.json'):
            options.extend(["-oJ", args.output])
        elif args.output.endswith('.yaml') or args.output.endswith('.yml'):
            options.extend(["-oY", args.output])
    
    # Create wrapper and run
    wrapper = Enum4linuxWrapper(use_ng=args.ng)
    return wrapper.run_null_session(args.target, options)


if __name__ == "__main__":
    sys.exit(main())
