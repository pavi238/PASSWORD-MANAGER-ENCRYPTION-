"""
main.py — Password Manager CLI Entry Point
============================================
A polished terminal-based Password Manager with:
- Colored ANSI banners and formatted menus
- Master password authentication
- Full CRUD operations on encrypted credentials
- Secure password generation
"""

import sys
import os

# Ensure the project root is on the import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ====================================================================== #
#  ANSI Color Codes (no external dependency)
# ====================================================================== #

class Colors:
    """ANSI escape codes for terminal coloring."""

    # Reset
    RESET = "\033[0m"

    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    # Background colors
    BG_BLUE = "\033[44m"
    BG_CYAN = "\033[46m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"

    @staticmethod
    def disable():
        """Disable all color codes (for non-ANSI terminals)."""
        for attr in dir(Colors):
            if not attr.startswith("_") and attr != "disable":
                if isinstance(getattr(Colors, attr), str):
                    setattr(Colors, attr, "")


# Enable Windows ANSI support
def _enable_windows_ansi():
    """Enable ANSI escape sequence processing on Windows 10+."""
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            # If it fails, disable colors gracefully
            Colors.disable()


_enable_windows_ansi()


# ====================================================================== #
#  Banner & Menu Display
# ====================================================================== #

def print_banner():
    """Print the application banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════╗
    ║                                                  ║
    ║   🔐  S E C U R E   V A U L T                   ║
    ║       Password Manager v1.0                      ║
    ║                                                  ║
    ║   ▪ AES-256 Encryption  ▪ Scrypt Hashing        ║
    ║   ▪ PBKDF2 Key Derivation                       ║
    ║                                                  ║
    ╚══════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def print_menu():
    """Print the main menu options."""
    print(f"""
  {Colors.CYAN}{'─' * 46}{Colors.RESET}
  {Colors.BOLD}  MAIN MENU{Colors.RESET}
  {Colors.CYAN}{'─' * 46}{Colors.RESET}

    {Colors.GREEN}1{Colors.RESET}.  ➕  Add New Credential
    {Colors.GREEN}2{Colors.RESET}.  📋  View All Credentials
    {Colors.GREEN}3{Colors.RESET}.  🔍  Search Credentials
    {Colors.GREEN}4{Colors.RESET}.  ✏️   Update a Credential
    {Colors.GREEN}5{Colors.RESET}.  🗑️   Delete a Credential
    {Colors.GREEN}6{Colors.RESET}.  🎲  Generate a Password
    {Colors.GREEN}7{Colors.RESET}.  🔄  Change Master Password
    {Colors.GREEN}0{Colors.RESET}.  🚪  Exit

  {Colors.CYAN}{'─' * 46}{Colors.RESET}
""")


# ====================================================================== #
#  Main Application Loop
# ====================================================================== #

def main():
    """Main entry point for the Password Manager."""
    from user import User
    from manager import PasswordManager
    from generator import PasswordGenerator
    from vault import Vault

    print_banner()

    user = User()
    vault = Vault()

    # ── First-time setup ──────────────────────────────────────────── #
    if not user.is_setup_complete():
        print(f"  {Colors.YELLOW}Welcome! This is your first time running Secure Vault.{Colors.RESET}")
        print(f"  {Colors.DIM}Let's set up your master password.{Colors.RESET}")

        if not user.setup_master_password():
            print(f"\n  {Colors.RED}Setup failed. Exiting.{Colors.RESET}")
            sys.exit(1)

    # ── Login ──────────────────────────────────────────────────────── #
    success, master_password = user.login()
    if not success:
        sys.exit(1)

    # ── Initialize Password Manager ───────────────────────────────── #
    pm = PasswordManager(master_password)

    print(f"\n  {Colors.DIM}Type a number to select an option.{Colors.RESET}")

    # ── Main Menu Loop ────────────────────────────────────────────── #
    while True:
        print_menu()
        choice = input(f"  {Colors.YELLOW}Enter choice ➜  {Colors.RESET}").strip()

        if choice == "1":
            pm.add_credential()

        elif choice == "2":
            pm.view_all()

        elif choice == "3":
            pm.search()

        elif choice == "4":
            pm.update_credential()

        elif choice == "5":
            pm.delete_credential()

        elif choice == "6":
            password = PasswordGenerator.interactive_generate()
            if password:
                print(f"\n  {Colors.DIM}Tip: You can also generate passwords when adding a new credential.{Colors.RESET}")

        elif choice == "7":
            success, new_password = user.change_master_password(master_password, vault)
            if success:
                master_password = new_password
                pm.update_master_password(new_password)

        elif choice == "0":
            print(f"\n  {Colors.CYAN}{'═' * 50}")
            print(f"  🔒  Vault locked. Goodbye!")
            print(f"  {'═' * 50}{Colors.RESET}\n")
            sys.exit(0)

        else:
            print(f"\n  {Colors.RED}✗  Invalid option. Please enter 0-7.{Colors.RESET}")

        # Pause before showing menu again
        input(f"\n  {Colors.DIM}Press Enter to continue...{Colors.RESET}")


if __name__ == "__main__":
    main()
