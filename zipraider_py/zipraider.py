#!/usr/bin/env python3
"""
ZipRaider - Simple ZIP Password Cracker
Author: Aryan Giri
"""

import os
import sys
import zipfile
import argparse
import itertools
import time
from pathlib import Path

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                      ZipRaider v1.0                          ║
║               Advanced ZIP Password Cracker                  ║
║                     Author: Aryan Giri                       ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_help_examples():
    """Show comprehensive help with examples"""
    examples = """
┌──────────────────────────────────────────────────────────────┐
│                     ZipRaider - Usage Examples               │
└──────────────────────────────────────────────────────────────┘

BASIC COMMANDS:
  python zipraider.py encrypted.zip
    -> Auto-detect best attack mode

  python zipraider.py encrypted.zip -h
    -> Show this help message

  python zipraider.py encrypted.zip --analyze
    -> Analyze ZIP file without cracking

DICTIONARY ATTACKS:
  python zipraider.py flag.zip -w rockyou.txt
    -> Dictionary attack with rockyou.txt

  python zipraider.py secret.zip -m dict -w custom.txt
    -> Dictionary attack with custom wordlist

  python zipraider.py data.zip -m dict -w /path/to/wordlist.txt
    -> Dictionary attack with specific wordlist

BRUTE FORCE ATTACKS:
  python zipraider.py pin.zip -m brute -c digits --min 4 --max 6
    -> Brute force 4-6 digit PIN

  python zipraider.py weak.zip -m brute -c lower --min 3 --max 5
    -> Brute force 3-5 lowercase letters

  python zipraider.py strong.zip -m brute -c alphanum --min 6 --max 8
    -> Brute force 6-8 alphanumeric characters

  python zipraider.py hex.zip -m brute -c hex --min 4 --max 8
    -> Brute force 4-8 hex characters (0-9, a-f)

CHARACTER SETS:
  -c lower     : a-z
  -c upper     : A-Z
  -c digits    : 0-9
  -c symbols   : !@#$%^&*() etc.
  -c alphanum  : a-zA-Z0-9
  -c all       : All printable characters
  -c hex       : 0-9a-f
  -c binary    : 01

EXTRACTION:
  python zipraider.py file.zip -o extracted_files
    -> Extract to custom directory

  python zipraider.py ctf.zip -w wordlist.txt -o flag
    -> Crack and extract to 'flag' directory

CTF SCENARIOS:
  # Common CTF passwords
  python zipraider.py flag.zip -m brute -c lower --min 5 --max 8
  
  # Year-based passwords
  python zipraider.py archive.zip -m brute -c digits --min 4 --max 4
  
  # Simple dictionary attack
  python zipraider.py secret.zip -w common_passwords.txt

WORDLIST TIPS:
  Default: rockyou.txt (included in Kali Linux)
  Download: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
  
  Create your own:
    echo -e "password\\n123456\\nadmin\\nletmein\\nqwerty\\nsecret" > mylist.txt

PERFORMANCE:
  • Dictionary attack is fastest for CTFs
  • Start with short brute force (1-4 chars)
  • Use appropriate charset (digits for PINs, lower for words)

TROUBLESHOOTING:
  • Ensure ZIP file is actually encrypted
  • Check file permissions
  • Use --analyze to examine ZIP first
  • Try different character sets

┌──────────────────────────────────────────────────────────────┐
│              Made for CTF Players by Aryan Giri              │
└──────────────────────────────────────────────────────────────┘
"""
    print(examples)

# Character sets for brute force
CHARSETS = {
    'lower': 'abcdefghijklmnopqrstuvwxyz',
    'upper': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'digits': '0123456789',
    'symbols': '!@#$%^&*()-_=+[]{}|;:,.<>?',
    'alphanum': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'all': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?',
    'hex': '0123456789abcdef',
    'binary': '01'
}

class ZipCracker:
    def __init__(self, zip_path):
        self.zip_path = zip_path
        self.attempts = 0
        self.start_time = None
        
    def test_password(self, password):
        """Test if password works for ZIP file"""
        try:
            with zipfile.ZipFile(self.zip_path) as zip_ref:
                file_list = zip_ref.namelist()
                if not file_list:
                    return False
                
                test_file = file_list[0]
                try:
                    zip_ref.extract(test_file, pwd=password.encode('utf-8', 'ignore'))
                    return True
                except:
                    return False
        except Exception as e:
            return False
    
    def analyze_zip(self):
        """Basic ZIP file analysis"""
        info = {
            'filename': os.path.basename(self.zip_path),
            'size': os.path.getsize(self.zip_path),
            'encrypted': False,
            'encryption_type': None,
            'file_count': 0
        }
        
        try:
            with zipfile.ZipFile(self.zip_path, 'r') as zip_ref:
                info['file_count'] = len(zip_ref.namelist())
                
                for file_info in zip_ref.infolist():
                    if file_info.flag_bits & 0x1:
                        info['encrypted'] = True
                        if file_info.flag_bits & 0x40:
                            info['encryption_type'] = 'AES-256'
                        elif file_info.flag_bits & 0x8000:
                            info['encryption_type'] = 'AES-128'
                        else:
                            info['encryption_type'] = 'ZipCrypto'
                        break
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def dictionary_attack(self, wordlist_path):
        """Simple dictionary attack"""
        self.start_time = time.time()
        
        print(f"[*] Starting dictionary attack...")
        
        if not os.path.exists(wordlist_path):
            print(f"[!] Wordlist not found: {wordlist_path}")
            return None
        
        try:
            with open(wordlist_path, 'r', errors='ignore', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            print(f"[*] Loaded {len(passwords):,} passwords from wordlist")
            
            for i, password in enumerate(passwords):
                self.attempts += 1
                
                if i % 1000 == 0 and i > 0:
                    elapsed = time.time() - self.start_time
                    speed = i / elapsed if elapsed > 0 else 0
                    print(f"[*] Tried {i:,} passwords ({speed:.0f} pwd/sec)...")
                
                if self.test_password(password):
                    return password
                
            return None
            
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def brute_force_attack(self, charset, min_len, max_len):
        """Simple brute force attack"""
        self.start_time = time.time()
        
        total_combinations = sum(len(charset) ** i for i in range(min_len, max_len + 1))
        print(f"[*] Starting brute force: {total_combinations:,} total combinations")
        
        try:
            for length in range(min_len, max_len + 1):
                print(f"[*] Testing length {length}...")
                
                total_for_length = len(charset) ** length
                
                for idx in range(total_for_length):
                    self.attempts += 1
                    
                    if self.attempts % 10000 == 0:
                        elapsed = time.time() - self.start_time
                        speed = self.attempts / elapsed if elapsed > 0 else 0
                        print(f"[*] Tried {self.attempts:,} passwords ({speed:.0f} pwd/sec)...")
                    
                    password = []
                    n = idx
                    for _ in range(length):
                        password.append(charset[n % len(charset)])
                        n //= len(charset)
                    password = ''.join(reversed(password))
                    
                    if self.test_password(password):
                        return password
                
            return None
            
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(
        description='ZipRaider - Simple ZIP Password Cracker by Aryan Giri',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Basic usage:
    python zipraider.py encrypted.zip
  
  Dictionary attack:
    python zipraider.py flag.zip -w rockyou.txt
    python zipraider.py secret.zip -m dict -w custom.txt
  
  Brute force attack:
    python zipraider.py pin.zip -m brute -c digits --min 4 --max 6
    python zipraider.py weak.zip -m brute -c lower --min 3 --max 5
  
  Analyze ZIP:
    python zipraider.py file.zip --analyze
  
  Extract to custom directory:
    python zipraider.py data.zip -w wordlist.txt -o extracted_files

CHARACTER SETS:
  lower    : a-z
  upper    : A-Z
  digits   : 0-9
  symbols  : !@#$%%^&*() etc.
  alphanum : a-zA-Z0-9
  all      : All printable characters
  hex      : 0-9a-f
  binary   : 01

TIPS:
  • CTF passwords are often simple - try dictionary first
  • Use --analyze to check encryption type
  • Start with short brute force ranges
  • Create custom wordlists for specific CTF challenges

For more examples: python zipraider.py --examples
        """
    )
    
    parser.add_argument('zipfile', help='Path to encrypted ZIP file')
    parser.add_argument('-w', '--wordlist', default='rockyou.txt', 
                       help='Wordlist file (default: %(default)s)')
    parser.add_argument('-m', '--mode', choices=['dict', 'brute'], default='dict',
                       help='Attack mode: dict (dictionary) or brute (brute force)')
    parser.add_argument('-c', '--charset', choices=list(CHARSETS.keys()), default='alphanum',
                       help='Character set for brute force (default: %(default)s)')
    parser.add_argument('--min', type=int, default=1,
                       help='Minimum password length for brute force (default: %(default)s)')
    parser.add_argument('--max', type=int, default=6,
                       help='Maximum password length for brute force (default: %(default)s)')
    parser.add_argument('-o', '--output', help='Output directory for extracted files')
    parser.add_argument('--analyze', action='store_true', 
                       help='Analyze ZIP file only (no cracking)')
    parser.add_argument('--examples', action='store_true',
                       help='Show detailed usage examples')
    
    # If no arguments provided
    if len(sys.argv) == 1:
        print_banner()
        print("\n" + "="*60)
        print("ZipRaider - ZIP Password Cracker")
        print("="*60)
        print("\nUsage: python zipraider.py ZIP_FILE [OPTIONS]")
        print("\nQuick Examples:")
        print("  python zipraider.py encrypted.zip")
        print("  python zipraider.py flag.zip -w wordlist.txt")
        print("  python zipraider.py pin.zip -m brute -c digits --min 4 --max 6")
        print("\nFor detailed help: python zipraider.py -h")
        print("For examples:      python zipraider.py --examples")
        print("="*60)
        sys.exit(0)
    
    args = parser.parse_args()
    
    # Show examples if requested
    if args.examples:
        print_banner()
        print_help_examples()
        sys.exit(0)
    
    print_banner()
    
    if not os.path.exists(args.zipfile):
        print(f"[!] ERROR: ZIP file '{args.zipfile}' not found!")
        sys.exit(1)
    
    # Initialize cracker
    cracker = ZipCracker(args.zipfile)
    
    # Analyze ZIP
    zip_info = cracker.analyze_zip()
    
    print("=" * 60)
    print("ZIP FILE ANALYSIS")
    print("=" * 60)
    print(f"  File: {zip_info['filename']}")
    print(f"  Size: {zip_info['size']:,} bytes")
    print(f"  Files: {zip_info.get('file_count', 0)}")
    
    if zip_info.get('encrypted', False):
        print(f"  Encryption: {zip_info.get('encryption_type', 'Unknown')}")
    else:
        print(f"  Encryption: None (file is not encrypted)")
        sys.exit(0)
    
    print("=" * 60)
    
    if args.analyze:
        sys.exit(0)
    
    # Check wordlist for dictionary attack
    if args.mode == 'dict' and not os.path.exists(args.wordlist):
        print(f"[!] ERROR: Wordlist '{args.wordlist}' not found!")
        
        if args.wordlist == 'rockyou.txt':
            print("\nYou can download rockyou.txt from:")
            print("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt")
            print("\nOr create a test wordlist:")
            print("echo -e 'password\\n123456\\nadmin\\nletmein\\nsecret' > wordlist.txt")
        
        sys.exit(1)
    
    # Start attack
    password = None
    
    try:
        if args.mode == 'dict':
            password = cracker.dictionary_attack(args.wordlist)
        elif args.mode == 'brute':
            charset = CHARSETS.get(args.charset, args.charset)
            password = cracker.brute_force_attack(charset, args.min, args.max)
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    
    # Show results
    print("\n" + "=" * 60)
    print("CRACKING RESULTS")
    print("=" * 60)
    
    elapsed = time.time() - cracker.start_time if cracker.start_time else 0
    
    if password:
        print(f"  [+] PASSWORD FOUND: {password}")
        print(f"  [+] Attempts: {cracker.attempts:,}")
        print(f"  [+] Time: {elapsed:.2f} seconds")
        if elapsed > 0:
            print(f"  [+] Speed: {cracker.attempts/elapsed:,.0f} pwd/sec")
        
        # Extract files
        try:
            output_dir = args.output or f"extracted_{Path(args.zipfile).stem}"
            os.makedirs(output_dir, exist_ok=True)
            
            with zipfile.ZipFile(args.zipfile) as zip_ref:
                zip_ref.extractall(path=output_dir, pwd=password.encode())
            
            print(f"  [+] Files extracted to: {output_dir}/")
            
            extracted_files = os.listdir(output_dir)
            if len(extracted_files) <= 10:
                print(f"\n  Extracted files:")
                for file in extracted_files:
                    print(f"    - {file}")
            else:
                print(f"    - {len(extracted_files)} files extracted")
        
        except Exception as e:
            print(f"  [!] Could not extract files: {e}")
    
    else:
        print(f"  [-] PASSWORD NOT FOUND")
        print(f"  [+] Attempts: {cracker.attempts:,}")
        print(f"  [+] Time: {elapsed:.2f} seconds")
        if elapsed > 0:
            print(f"  [+] Speed: {cracker.attempts/elapsed:,.0f} pwd/sec")
        
        print("\n  [!] Suggestions:")
        print("      - Try a different wordlist")
        print("      - Increase brute force length range")
        print("      - Check if the ZIP file is actually encrypted")
    
    print("=" * 60)
    print("ZipRaider - ZIP Cracker by Aryan Giri")
    print("=" * 60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
