#!/usr/bin/env python3
import hashlib
import argparse
import sys
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class HashAuditor:
    def __init__(self):
        # DYNAMICALLY load all available algorithms from hashlib
        # This will include md5, sha1, sha224, sha256, sha384, sha512,
        # blake2b, blake2s, sha3_224, sha3_256, sha3_384, sha3_512,
        # shake_128, shake_256, and others depending on your OpenSSL version.
        self.algorithms = {}
        
        # We use algorithms_available to get everything supported by the system
        for algo in hashlib.algorithms_available:
            try:
                # Test if we can load it to be sure
                hashlib.new(algo)
                self.algorithms[algo] = algo
            except:
                continue

    def print_banner(self):
        banner = fr"""
{Fore.CYAN}    __  __            __       ___            __{Style.RESET_ALL}
{Fore.CYAN}   / / / /___ ______/ /_     /   | __  ______/ /____{Style.RESET_ALL}
{Fore.CYAN}  / /_/ / __ `/ ___/ __ \   / /| |/ / / / __  / ___/{Style.RESET_ALL}
{Fore.CYAN} / __  / /_/ (__  ) / / /  / ___ / /_/ / /_/ (__  ) {Style.RESET_ALL}
{Fore.CYAN}/_/ /_/\__,_/____/_/ /_/  /_/  |_\__,_/\__,_/____/  {Style.RESET_ALL}
                                     {Fore.MAGENTA}By Smokie | https://github.com/Sm7kie{Style.RESET_ALL}
        """
        print(banner)

    def save_output(self, filename, data):
        try:
            with open(filename, 'a') as f:
                f.write(data + "\n")
            print(f"{Fore.GREEN}[*] Result saved to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving file: {e}{Style.RESET_ALL}")

    def generate_hash(self, text, algo_name, salt=""):
        if algo_name not in self.algorithms:
            return None, f"Algorithm '{algo_name}' not supported."
        
        try:
            # Create the hash object dynamically
            h = hashlib.new(algo_name)
            
            # Combine password and salt
            input_data = (text + salt).encode('utf-8')
            h.update(input_data)
            
            # SHAKE algorithms require a length argument for hexdigest
            if algo_name.startswith('shake_'):
                return h.hexdigest(64), None # Default to 64 bytes for shake
            
            return h.hexdigest(), None
        except Exception as e:
            return None, str(e)

    def identify_hash_candidates(self, hash_str):
        """Smart Auto-Detect: Checks length against all loaded algos."""
        length = len(hash_str)
        candidates = []
        
        # We test a dummy hash for every algorithm to see if length matches
        # This is slower but 100% accurate for all system algorithms
        dummy_text = b"test"
        
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Analyzing hash length ({length})...")
        
        for algo in self.algorithms:
            try:
                h = hashlib.new(algo)
                h.update(dummy_text)
                
                # Handle SHAKE variable length (we skip variable length for auto-detect usually)
                if algo.startswith('shake_'): continue

                if len(h.hexdigest()) == length:
                    candidates.append(algo)
            except:
                continue
                
        return list(set(candidates)) # Remove duplicates

    def crack_hash(self, target_hash, wordlist_path, algo_name=None, salt="", output_file=None):
        target_hash = target_hash.strip()
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Target: {target_hash}")
        
        algos_to_try = []
        if algo_name:
            if algo_name not in self.algorithms:
                print(f"{Fore.RED}[!] Algorithm '{algo_name}' not supported.{Style.RESET_ALL}")
                return
            algos_to_try.append(algo_name)
        else:
            algos_to_try = self.identify_hash_candidates(target_hash)
            if not algos_to_try:
                print(f"{Fore.RED}[!] Could not auto-detect hash type.{Style.RESET_ALL}")
                return
            print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Candidates: {Fore.YELLOW}{', '.join(algos_to_try)}{Style.RESET_ALL}")

        if salt: print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Using Salt: {Fore.MAGENTA}{salt}{Style.RESET_ALL}")

        if not os.path.exists(wordlist_path):
            print(f"{Fore.RED}[!] Error: Wordlist file '{wordlist_path}' not found.{Style.RESET_ALL}")
            return

        print(f"{Fore.YELLOW}[*] Starting attack...{Style.RESET_ALL}")
        
        try:
            found = False
            with open(wordlist_path, 'r', encoding='latin-1') as f:
                for line in f:
                    word = line.strip()
                    for algo in algos_to_try:
                        curr_hash, _ = self.generate_hash(word, algo, salt)
                        if curr_hash == target_hash:
                            success_msg = f"[+] SUCCESS! Password Found: {word} (Algo: {algo})"
                            print(f"\n{Fore.GREEN}{success_msg}{Style.RESET_ALL}")
                            
                            if output_file:
                                self.save_output(output_file, f"Hash: {target_hash} | Password: {word} | Algo: {algo}")
                            
                            found = True
                            break
                    if found: break
            if not found:
                print(f"\n{Fore.RED}[-] Password not found in wordlist.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")

    def get_algo_choice(self):
        print(f"\n{Fore.CYAN}Available Algorithms:{Style.RESET_ALL}")
        algo_list = sorted(list(self.algorithms.keys()))
        
        # Display in columns of 3 to save space
        for i in range(0, len(algo_list), 3):
            chunk = algo_list[i:i+3]
            line = ""
            for j, algo in enumerate(chunk):
                idx = i + j + 1
                line += f"[{Fore.GREEN}{idx}{Style.RESET_ALL}] {algo:<15} "
            print(line)
            
        choice = input(f"\n{Fore.YELLOW}Select Algorithm (Enter number, default sha256) > {Style.RESET_ALL}")
        if not choice: return "sha256"
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(algo_list): return algo_list[idx]
        return "sha256"

    def interactive_mode(self):
        while True:
            print(f"\n{Fore.CYAN}--- Menu Selection ---{Style.RESET_ALL}")
            print(f"[{Fore.GREEN}1{Style.RESET_ALL}] Generate Hash")
            print(f"[{Fore.GREEN}2{Style.RESET_ALL}] Crack Hash")
            print(f"[{Fore.RED}3{Style.RESET_ALL}] Exit")
            
            choice = input(f"\n{Fore.YELLOW}Select an option > {Style.RESET_ALL}")

            if choice == '1':
                text = input("Enter text to hash: ")
                salt = input("Enter salt (optional): ")
                algo = self.get_algo_choice()
                save_opt = input("Save output to file? (y/N): ")
                
                result, error = self.generate_hash(text, algo, salt)
                if error: print(f"{Fore.RED}[!] {error}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Hash ({algo}): {result}{Style.RESET_ALL}")
                    if save_opt.lower() == 'y':
                        filename = input("Enter filename: ")
                        self.save_output(filename, f"Input: {text} | Salt: {salt} | Algo: {algo} | Hash: {result}")

            elif choice == '2':
                target = input("Enter hash to crack: ").strip()
                wordlist = input("Enter path to wordlist: ").strip()
                salt = input("Enter salt (optional): ")
                save_opt = input("Save result to file? (y/N): ")
                output_file = None
                if save_opt.lower() == 'y':
                    output_file = input("Enter filename: ")

                print(f"\n{Fore.CYAN}Select Algorithm{Style.RESET_ALL}")
                algo_choice = input(f"{Fore.YELLOW}Press Enter for Auto-Detect, or type 'L' to choose > {Style.RESET_ALL}")
                algo = None
                if algo_choice.lower() == 'l':
                    algo = self.get_algo_choice()

                self.crack_hash(target, wordlist, algo, salt, output_file)

            elif choice == '3':
                sys.exit()

def main():
    tool = HashAuditor()
    tool.print_banner()

    if len(sys.argv) == 1:
        tool.interactive_mode()
        sys.exit()

    parser = argparse.ArgumentParser()
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-g", "--generate", help="Generate a hash", type=str)
    mode_group.add_argument("-c", "--crack", help="Crack a hash", type=str)
    
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-a", "--algo", help="Algorithm", default=None)
    parser.add_argument("-s", "--salt", help="Salt string", default="", type=str)
    parser.add_argument("-o", "--output", help="Save output to file", type=str)
    parser.add_argument("--list", help="List algorithms", action="store_true")

    args = parser.parse_args()

    if args.list:
        print(f"{Fore.CYAN}Supported Algorithms:{Style.RESET_ALL}")
        for algo in sorted(tool.algorithms.keys()): print(f" - {algo}")
        sys.exit()

    if args.generate:
        algo = args.algo if args.algo else "sha256"
        result, error = tool.generate_hash(args.generate, algo, args.salt)
        if error: print(f"{Fore.RED}[!] {error}{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}[*] Input:{Style.RESET_ALL} {args.generate}")
            if args.salt: print(f"{Fore.BLUE}[*] Salt:{Style.RESET_ALL} {args.salt}")
            print(f"{Fore.GREEN}[+] Hash ({algo}):{Style.RESET_ALL} {result}")
            
            if args.output:
                tool.save_output(args.output, f"Input: {args.generate} | Salt: {args.salt} | Algo: {algo} | Hash: {result}")

    elif args.crack:
        if not args.wordlist:
            print(f"{Fore.RED}[!] Error: --wordlist is required for cracking mode.{Style.RESET_ALL}")
        else:
            tool.crack_hash(args.crack.strip(), args.wordlist, args.algo, args.salt, args.output)

if __name__ == "__main__":
    main()
