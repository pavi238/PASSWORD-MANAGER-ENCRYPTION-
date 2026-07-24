"""
manager.py — Password Manager (CRUD Operations)
=================================================
Orchestrates all Create, Read, Update, Delete operations on
the encrypted credential vault. Each mutation automatically
re-encrypts and saves the vault to disk.
"""

import getpass
from datetime import datetime

from vault import Vault
from generator import PasswordGenerator


class PasswordManager:
    """
    Manages the lifecycle of stored credentials.

    Each credential entry is a dictionary:
    {
        "service":    "GitHub",
        "username":   "user@example.com",
        "password":   "s3cur3P@ss!",
        "created_at": "2026-07-24 12:00:00",
        "updated_at": "2026-07-24 12:00:00"
    }
    """

    def __init__(self, master_password: str):
        """
        Initialize the PasswordManager.

        Args:
            master_password: The verified master password (used for vault encryption).
        """
        self.master_password = master_password
        self.vault = Vault()
        self._entries: list[dict] = []
        self._load_entries()

    def _load_entries(self) -> None:
        """Load entries from the encrypted vault into memory."""
        try:
            self._entries = self.vault.load(self.master_password)
        except Exception:
            self._entries = []

    def _save_entries(self) -> None:
        """Encrypt and save the current entries to the vault file."""
        self.vault.save(self._entries, self.master_password)

    def _now(self) -> str:
        """Return the current timestamp as a formatted string."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _copy_to_clipboard(self, text: str) -> bool:
        """Copy text to clipboard on Windows using built-in clip command."""
        import subprocess
        try:
            process = subprocess.Popen(['clip'], stdin=subprocess.PIPE, text=True)
            process.communicate(input=text)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    #  CRUD Operations
    # ------------------------------------------------------------------ #

    def add_credential(self) -> None:
        """
        Interactively add a new credential to the vault.

        Prompts for service name, username, and password.
        Offers the option to auto-generate a secure password.
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  ➕  ADD NEW CREDENTIAL")
        print(f"{'═' * 50}{Colors.RESET}\n")

        service = input(f"  {Colors.YELLOW}Service name (e.g., GitHub): {Colors.RESET}").strip()
        if not service:
            print(f"  {Colors.RED}✗  Service name cannot be empty.{Colors.RESET}")
            return

        username = input(f"  {Colors.YELLOW}Username / Email: {Colors.RESET}").strip()
        if not username:
            print(f"  {Colors.RED}✗  Username cannot be empty.{Colors.RESET}")
            return

        # Password entry
        print(f"\n  {Colors.DIM}How would you like to set the password?{Colors.RESET}")
        print(f"    {Colors.BOLD}1{Colors.RESET}. Enter manually")
        print(f"    {Colors.BOLD}2{Colors.RESET}. Auto-generate a secure password")

        choice = input(f"\n  {Colors.YELLOW}Choice [1/2]: {Colors.RESET}").strip()

        if choice == "2":
            password = PasswordGenerator.interactive_generate()
            if password is None:
                print(f"  {Colors.RED}✗  Credential creation cancelled.{Colors.RESET}")
                return
        else:
            password = getpass.getpass(f"  {Colors.YELLOW}Password: {Colors.RESET}")
            if not password:
                print(f"  {Colors.RED}✗  Password cannot be empty.{Colors.RESET}")
                return

            # Show strength
            rating, score, color = PasswordGenerator.evaluate_strength(password)
            print(f"  {Colors.DIM}Strength:{Colors.RESET} {color}{rating} ({score}/100){Colors.RESET}")

        # Check for duplicate service
        for entry in self._entries:
            if entry["service"].lower() == service.lower() and entry["username"].lower() == username.lower():
                print(f"\n  {Colors.RED}⚠  A credential for '{service}' with username '{username}' already exists.{Colors.RESET}")
                overwrite = input(f"  {Colors.YELLOW}Overwrite? [y/N]: {Colors.RESET}").strip().lower()
                if overwrite in ("y", "yes"):
                    entry["password"] = password
                    entry["updated_at"] = self._now()
                    self._save_entries()
                    print(f"\n  {Colors.GREEN}✅  Credential updated successfully!{Colors.RESET}")
                else:
                    print(f"  {Colors.DIM}  Operation cancelled.{Colors.RESET}")
                return

        # Add new entry
        new_entry = {
            "service": service,
            "username": username,
            "password": password,
            "created_at": self._now(),
            "updated_at": self._now(),
        }
        self._entries.append(new_entry)
        self._save_entries()

        print(f"\n  {Colors.GREEN}✅  Credential for '{service}' saved successfully!{Colors.RESET}")

    def view_all(self) -> None:
        """
        Display all stored credentials in a formatted table.
        Passwords are masked by default with an option to reveal.
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  📋  ALL STORED CREDENTIALS")
        print(f"{'═' * 50}{Colors.RESET}\n")

        if not self._entries:
            print(f"  {Colors.DIM}No credentials stored yet. Use 'Add' to create one.{Colors.RESET}")
            return

        # Ask if user wants to reveal passwords
        reveal = input(f"  {Colors.YELLOW}Reveal passwords? [y/N]: {Colors.RESET}").strip().lower()
        show_password = reveal in ("y", "yes")

        print()
        self._print_entries_table(self._entries, show_password)
        print(f"\n  {Colors.DIM}Total: {len(self._entries)} credential(s){Colors.RESET}")

        # Offer clipboard option
        copy_choice = input(f"\n  {Colors.YELLOW}Would you like to copy a password to clipboard? [y/N]: {Colors.RESET}").strip().lower()
        if copy_choice in ("y", "yes"):
            try:
                idx = int(input(f"  {Colors.YELLOW}Select entry number to copy (1-{len(self._entries)}): {Colors.RESET}").strip()) - 1
                if 0 <= idx < len(self._entries):
                    target = self._entries[idx]
                    if self._copy_to_clipboard(target["password"]):
                        print(f"  {Colors.GREEN}✅  Password for '{target['service']}' copied to clipboard!{Colors.RESET}")
                    else:
                        print(f"  {Colors.RED}✗  Could not copy to clipboard.{Colors.RESET}")
                else:
                    print(f"  {Colors.RED}✗  Invalid entry number.{Colors.RESET}")
            except ValueError:
                print(f"  {Colors.RED}✗  Invalid entry number.{Colors.RESET}")

    def search(self) -> None:
        """
        Search credentials by service name or username.
        Case-insensitive partial matching.
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  🔍  SEARCH CREDENTIALS")
        print(f"{'═' * 50}{Colors.RESET}\n")

        if not self._entries:
            print(f"  {Colors.DIM}No credentials stored yet.{Colors.RESET}")
            return

        query = input(f"  {Colors.YELLOW}Search query: {Colors.RESET}").strip().lower()
        if not query:
            print(f"  {Colors.RED}✗  Search query cannot be empty.{Colors.RESET}")
            return

        # Search in service name and username
        results = [
            entry for entry in self._entries
            if query in entry["service"].lower() or query in entry["username"].lower()
        ]

        if not results:
            print(f"\n  {Colors.DIM}No matching credentials found for '{query}'.{Colors.RESET}")
            return

        print(f"\n  {Colors.GREEN}Found {len(results)} result(s):{Colors.RESET}\n")

        reveal = input(f"  {Colors.YELLOW}Reveal passwords? [y/N]: {Colors.RESET}").strip().lower()
        show_password = reveal in ("y", "yes")

        print()
        self._print_entries_table(results, show_password)

        # Offer clipboard option
        copy_choice = input(f"\n  {Colors.YELLOW}Would you like to copy a password to clipboard? [y/N]: {Colors.RESET}").strip().lower()
        if copy_choice in ("y", "yes"):
            try:
                idx = int(input(f"  {Colors.YELLOW}Select entry number to copy (1-{len(results)}): {Colors.RESET}").strip()) - 1
                if 0 <= idx < len(results):
                    target = results[idx]
                    if self._copy_to_clipboard(target["password"]):
                        print(f"  {Colors.GREEN}✅  Password for '{target['service']}' copied to clipboard!{Colors.RESET}")
                    else:
                        print(f"  {Colors.RED}✗  Could not copy to clipboard.{Colors.RESET}")
                else:
                    print(f"  {Colors.RED}✗  Invalid entry number.{Colors.RESET}")
            except ValueError:
                print(f"  {Colors.RED}✗  Invalid entry number.{Colors.RESET}")

    def update_credential(self) -> None:
        """
        Update an existing credential's username or password.
        Finds the credential by service name.
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  ✏️   UPDATE CREDENTIAL")
        print(f"{'═' * 50}{Colors.RESET}\n")

        if not self._entries:
            print(f"  {Colors.DIM}No credentials stored yet.{Colors.RESET}")
            return

        service = input(f"  {Colors.YELLOW}Service name to update: {Colors.RESET}").strip()
        if not service:
            print(f"  {Colors.RED}✗  Service name cannot be empty.{Colors.RESET}")
            return

        # Find matching entries
        matches = [e for e in self._entries if e["service"].lower() == service.lower()]

        if not matches:
            print(f"\n  {Colors.RED}✗  No credential found for '{service}'.{Colors.RESET}")
            return

        # If multiple matches, let user pick
        if len(matches) > 1:
            print(f"\n  {Colors.DIM}Multiple accounts found for '{service}':{Colors.RESET}\n")
            for i, entry in enumerate(matches, 1):
                print(f"    {Colors.BOLD}{i}{Colors.RESET}. {entry['username']}")
            print()

            try:
                idx = int(input(f"  {Colors.YELLOW}Select account number: {Colors.RESET}").strip()) - 1
                if idx < 0 or idx >= len(matches):
                    print(f"  {Colors.RED}✗  Invalid selection.{Colors.RESET}")
                    return
                target = matches[idx]
            except (ValueError, IndexError):
                print(f"  {Colors.RED}✗  Invalid selection.{Colors.RESET}")
                return
        else:
            target = matches[0]

        print(f"\n  {Colors.DIM}Current: {target['service']} — {target['username']}{Colors.RESET}")
        print(f"\n  {Colors.DIM}Leave blank to keep current value.{Colors.RESET}\n")

        # Update username
        new_username = input(f"  {Colors.YELLOW}New username [{target['username']}]: {Colors.RESET}").strip()
        if new_username:
            target["username"] = new_username

        # Update password
        print(f"\n    {Colors.BOLD}1{Colors.RESET}. Enter new password manually")
        print(f"    {Colors.BOLD}2{Colors.RESET}. Auto-generate new password")
        print(f"    {Colors.BOLD}3{Colors.RESET}. Keep current password")

        choice = input(f"\n  {Colors.YELLOW}Choice [1/2/3]: {Colors.RESET}").strip()

        if choice == "1":
            new_password = getpass.getpass(f"  {Colors.YELLOW}New password: {Colors.RESET}")
            if new_password:
                target["password"] = new_password
                rating, score, color = PasswordGenerator.evaluate_strength(new_password)
                print(f"  {Colors.DIM}Strength:{Colors.RESET} {color}{rating} ({score}/100){Colors.RESET}")
        elif choice == "2":
            new_password = PasswordGenerator.interactive_generate()
            if new_password:
                target["password"] = new_password

        target["updated_at"] = self._now()
        self._save_entries()

        print(f"\n  {Colors.GREEN}✅  Credential for '{target['service']}' updated!{Colors.RESET}")

    def delete_credential(self) -> None:
        """
        Delete a credential from the vault by service name.
        Requires confirmation before deletion.
        """
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  🗑️   DELETE CREDENTIAL")
        print(f"{'═' * 50}{Colors.RESET}\n")

        if not self._entries:
            print(f"  {Colors.DIM}No credentials stored yet.{Colors.RESET}")
            return

        service = input(f"  {Colors.YELLOW}Service name to delete: {Colors.RESET}").strip()
        if not service:
            print(f"  {Colors.RED}✗  Service name cannot be empty.{Colors.RESET}")
            return

        matches = [e for e in self._entries if e["service"].lower() == service.lower()]

        if not matches:
            print(f"\n  {Colors.RED}✗  No credential found for '{service}'.{Colors.RESET}")
            return

        # If multiple matches
        if len(matches) > 1:
            print(f"\n  {Colors.DIM}Multiple accounts found for '{service}':{Colors.RESET}\n")
            for i, entry in enumerate(matches, 1):
                print(f"    {Colors.BOLD}{i}{Colors.RESET}. {entry['username']}")
            print()

            try:
                idx = int(input(f"  {Colors.YELLOW}Select account to delete: {Colors.RESET}").strip()) - 1
                if idx < 0 or idx >= len(matches):
                    print(f"  {Colors.RED}✗  Invalid selection.{Colors.RESET}")
                    return
                target = matches[idx]
            except (ValueError, IndexError):
                print(f"  {Colors.RED}✗  Invalid selection.{Colors.RESET}")
                return
        else:
            target = matches[0]

        # Confirm deletion
        print(f"\n  {Colors.RED}⚠  You are about to delete:{Colors.RESET}")
        print(f"     Service:  {target['service']}")
        print(f"     Username: {target['username']}")

        confirm = input(f"\n  {Colors.YELLOW}Are you sure? [y/N]: {Colors.RESET}").strip().lower()
        if confirm not in ("y", "yes"):
            print(f"  {Colors.DIM}  Deletion cancelled.{Colors.RESET}")
            return

        self._entries.remove(target)
        self._save_entries()

        print(f"\n  {Colors.GREEN}✅  Credential deleted successfully!{Colors.RESET}")

    # ------------------------------------------------------------------ #
    #  Display Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _print_entries_table(entries: list[dict], show_password: bool = False) -> None:
        """
        Print a list of credential entries as a formatted table.

        Args:
            entries: List of credential dicts.
            show_password: If True, show passwords in plaintext; otherwise mask them.
        """
        from main import Colors

        # Calculate column widths
        svc_w = max(len("Service"), max(len(e["service"]) for e in entries))
        usr_w = max(len("Username"), max(len(e["username"]) for e in entries))
        pwd_w = max(len("Password"), 16)
        date_w = len("Updated At")

        # Clamp widths
        svc_w = min(svc_w, 25)
        usr_w = min(usr_w, 30)

        # Header
        header = (
            f"  {Colors.BOLD}{'#':<4}"
            f"{'Service':<{svc_w + 2}}"
            f"{'Username':<{usr_w + 2}}"
            f"{'Password':<{pwd_w + 2}}"
            f"{'Updated At':<{date_w}}{Colors.RESET}"
        )
        separator = f"  {'─' * (4 + svc_w + 2 + usr_w + 2 + pwd_w + 2 + date_w)}"

        print(header)
        print(separator)

        # Rows
        for i, entry in enumerate(entries, 1):
            service = entry["service"][:25]
            username = entry["username"][:30]
            password = entry["password"] if show_password else "•" * min(len(entry["password"]), 12)
            updated = entry.get("updated_at", entry.get("created_at", "N/A"))

            row = (
                f"  {Colors.DIM}{i:<4}{Colors.RESET}"
                f"{Colors.WHITE}{service:<{svc_w + 2}}{Colors.RESET}"
                f"{username:<{usr_w + 2}}"
                f"{Colors.GREEN if show_password else Colors.DIM}{password:<{pwd_w + 2}}{Colors.RESET}"
                f"{Colors.DIM}{updated:<{date_w}}{Colors.RESET}"
            )
            print(row)

    def update_master_password(self, new_password: str) -> None:
        """
        Update the internal master password reference after a password change.

        Args:
            new_password: The new master password.
        """
        self.master_password = new_password
