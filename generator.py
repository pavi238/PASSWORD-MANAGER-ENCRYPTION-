"""
generator.py — Secure Password Generator
==========================================
Generates cryptographically secure random passwords using the
`secrets` module. Supports configurable length and character sets,
and provides a password strength rating.
"""

import secrets
import string


class PasswordGenerator:
    """
    Generates strong, random passwords with configurable options.

    Uses `secrets.choice()` for cryptographically secure randomness
    (backed by os.urandom / the system CSPRNG).
    """

    # Character pools
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"

    @staticmethod
    def generate(
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        """
        Generate a cryptographically secure random password.

        The algorithm guarantees at least one character from each enabled
        category, then fills the remaining length with random picks from
        the combined pool, and finally shuffles the result.

        Args:
            length: Desired password length (minimum 4, default 16).
            use_uppercase: Include uppercase letters.
            use_lowercase: Include lowercase letters.
            use_digits: Include digits.
            use_symbols: Include special characters.

        Returns:
            A random password string.

        Raises:
            ValueError: If no character sets are enabled or length is too short.
        """
        # Build the character pool and mandatory characters
        pool = ""
        mandatory = []

        if use_lowercase:
            pool += PasswordGenerator.LOWERCASE
            mandatory.append(secrets.choice(PasswordGenerator.LOWERCASE))
        if use_uppercase:
            pool += PasswordGenerator.UPPERCASE
            mandatory.append(secrets.choice(PasswordGenerator.UPPERCASE))
        if use_digits:
            pool += PasswordGenerator.DIGITS
            mandatory.append(secrets.choice(PasswordGenerator.DIGITS))
        if use_symbols:
            pool += PasswordGenerator.SYMBOLS
            mandatory.append(secrets.choice(PasswordGenerator.SYMBOLS))

        if not pool:
            raise ValueError("At least one character set must be enabled.")

        min_length = max(len(mandatory), 4)
        if length < min_length:
            length = min_length

        # Fill remaining slots
        remaining = length - len(mandatory)
        password_chars = mandatory + [secrets.choice(pool) for _ in range(remaining)]

        # Shuffle to avoid predictable positions of mandatory characters
        # Using Fisher-Yates shuffle with secrets for secure randomness
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)

    @staticmethod
    def evaluate_strength(password: str) -> tuple[str, int, str]:
        """
        Evaluate the strength of a password.

        Scoring criteria:
        - Length contribution (up to 30 points)
        - Character variety (up to 40 points)
        - Bonus for mixing categories (up to 30 points)

        Args:
            password: The password to evaluate.

        Returns:
            A tuple of (rating_label, score_out_of_100, color_code).
        """
        score = 0
        length = len(password)

        # Length scoring (max 30)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 22
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 8
        else:
            score += 3

        # Character variety scoring (max 40)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in PasswordGenerator.SYMBOLS for c in password)

        variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_count * 10

        # Bonus for mixing all categories (max 30)
        if variety_count == 4:
            score += 20
        elif variety_count == 3:
            score += 10
        elif variety_count == 2:
            score += 5

        # Additional bonus for length > 20
        if length > 20:
            score += 10

        # Cap at 100
        score = min(score, 100)

        # Determine rating
        if score >= 80:
            return ("Very Strong 💪", score, "\033[92m")   # Bright green
        elif score >= 60:
            return ("Strong 🔒", score, "\033[32m")         # Green
        elif score >= 40:
            return ("Medium ⚡", score, "\033[33m")          # Yellow
        else:
            return ("Weak ⚠️", score, "\033[91m")            # Red

    @staticmethod
    def interactive_generate() -> str | None:
        """
        Interactive password generation with user configuration.

        Prompts the user for length and character set preferences,
        generates the password, displays it with a strength rating,
        and offers to regenerate.

        Returns:
            The generated password string, or None if cancelled.
        """
        # Import Colors here to avoid circular imports
        from main import Colors

        print(f"\n{Colors.CYAN}{'═' * 50}")
        print(f"  🎲  PASSWORD GENERATOR")
        print(f"{'═' * 50}{Colors.RESET}\n")

        # Get length
        while True:
            length_input = input(f"  {Colors.YELLOW}Password length (default 16): {Colors.RESET}").strip()
            if length_input == "":
                length = 16
                break
            try:
                length = int(length_input)
                if length < 4:
                    print(f"  {Colors.RED}Minimum length is 4.{Colors.RESET}")
                    continue
                if length > 128:
                    print(f"  {Colors.RED}Maximum length is 128.{Colors.RESET}")
                    continue
                break
            except ValueError:
                print(f"  {Colors.RED}Please enter a valid number.{Colors.RESET}")

        # Get character set preferences
        def ask_yes_no(prompt: str, default: bool = True) -> bool:
            default_str = "Y/n" if default else "y/N"
            answer = input(f"  {Colors.YELLOW}{prompt} [{default_str}]: {Colors.RESET}").strip().lower()
            if answer == "":
                return default
            return answer in ("y", "yes")

        use_uppercase = ask_yes_no("Include uppercase letters?")
        use_lowercase = ask_yes_no("Include lowercase letters?")
        use_digits = ask_yes_no("Include digits?")
        use_symbols = ask_yes_no("Include symbols?")

        while True:
            try:
                password = PasswordGenerator.generate(
                    length=length,
                    use_uppercase=use_uppercase,
                    use_lowercase=use_lowercase,
                    use_digits=use_digits,
                    use_symbols=use_symbols,
                )
            except ValueError as e:
                print(f"\n  {Colors.RED}Error: {e}{Colors.RESET}")
                return None

            # Display result
            rating, score, color = PasswordGenerator.evaluate_strength(password)

            print(f"\n  {'─' * 46}")
            print(f"  {Colors.BOLD}Generated Password:{Colors.RESET}")
            print(f"\n    {Colors.GREEN}{Colors.BOLD}{password}{Colors.RESET}\n")
            print(f"  {Colors.DIM}Length:{Colors.RESET} {len(password)}")
            print(f"  {Colors.DIM}Strength:{Colors.RESET} {color}{rating} ({score}/100){Colors.RESET}")
            print(f"  {'─' * 46}")

            # Offer to regenerate
            action = input(f"\n  {Colors.YELLOW}[R]egenerate / [U]se this / [C]ancel: {Colors.RESET}").strip().lower()
            if action in ("u", "use"):
                return password
            elif action in ("c", "cancel"):
                return None
            # Default: regenerate (loop continues)
