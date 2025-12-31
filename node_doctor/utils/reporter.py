"""
Utilities for formatting and displaying check results.
"""

from typing import List, Dict
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class CheckResult:
    """Represents the result of a single check."""
    
    def __init__(
        self,
        check_id: str,
        name: str,
        status: str,  # "pass", "fail", "warn", "skip", "error"
        severity: str,
        message: str,
        recommendation: str = "",
        details: Dict = None
    ):
        self.check_id = check_id
        self.name = name
        self.status = status
        self.severity = severity
        self.message = message
        self.recommendation = recommendation
        self.details = details or {}
    
    def __repr__(self):
        return f"CheckResult({self.check_id}: {self.status})"


class Reporter:
    """Formats and displays check results."""
    
    SEVERITY_SYMBOLS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢"
    }
    
    STATUS_SYMBOLS = {
        "pass": "✅",
        "fail": "❌",
        "warn": "⚠️",
        "skip": "⏭️",
        "error": "💥"
    }
    
    STATUS_COLORS = {
        "pass": Fore.GREEN,
        "fail": Fore.RED,
        "warn": Fore.YELLOW,
        "skip": Fore.CYAN,
        "error": Fore.MAGENTA
    }
    
    def __init__(self):
        self.results: List[CheckResult] = []
    
    def add_result(self, result: CheckResult):
        """Add a check result."""
        self.results.append(result)
    
    def print_summary(self):
        """Print a summary of all results."""
        if not self.results:
            print("No checks were run.")
            return
        
        print("\n" + "=" * 70)
        print("CHECK RESULTS SUMMARY")
        print("=" * 70 + "\n")
        
        # Group by category
        by_category = {}
        for result in self.results:
            category = result.details.get("category", "Unknown")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(result)
        
        # Print each category
        for category, results in by_category.items():
            print(f"\n{Style.BRIGHT}{category.upper().replace('_', ' ')}{Style.RESET_ALL}")
            print("-" * 70)
            
            for result in results:
                self._print_result(result)
        
        # Print statistics
        self._print_statistics()
    
    def _print_result(self, result: CheckResult):
        """Print a single check result."""
        severity_symbol = self.SEVERITY_SYMBOLS.get(result.severity, "")
        status_symbol = self.STATUS_SYMBOLS.get(result.status, "")
        status_color = self.STATUS_COLORS.get(result.status, "")
        
        # Main result line
        print(f"{status_symbol} {severity_symbol} {result.check_id}: {result.name}")
        print(f"   {status_color}{result.status.upper()}{Style.RESET_ALL}: {result.message}")
        
        # Show recommendation for failures and warnings
        if result.status in ["fail", "warn"] and result.recommendation:
            print(f"   {Fore.CYAN}Recommendation:{Style.RESET_ALL}")
            for line in result.recommendation.strip().split('\n'):
                if line.strip():
                    print(f"   {line}")
        
        print()  # Blank line between results
    
    def _print_statistics(self):
        """Print summary statistics."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.status == "pass")
        failed = sum(1 for r in self.results if r.status == "fail")
        warned = sum(1 for r in self.results if r.status == "warn")
        skipped = sum(1 for r in self.results if r.status == "skip")
        errors = sum(1 for r in self.results if r.status == "error")
        
        print("\n" + "=" * 70)
        print("STATISTICS")
        print("=" * 70)
        print(f"Total checks:    {total}")
        print(f"{Fore.GREEN}Passed:          {passed}{Style.RESET_ALL}")
        print(f"{Fore.RED}Failed:          {failed}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Warnings:        {warned}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Skipped:         {skipped}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Errors:          {errors}{Style.RESET_ALL}")
        
        # Overall assessment
        print("\n" + "=" * 70)
        if failed == 0 and errors == 0:
            print(f"{Fore.GREEN}{Style.BRIGHT}✅ No critical issues found!{Style.RESET_ALL}")
        elif failed > 0:
            print(f"{Fore.RED}{Style.BRIGHT}⚠️  {failed} check(s) failed - please review recommendations{Style.RESET_ALL}")
        
        if errors > 0:
            print(f"{Fore.MAGENTA}⚠️  {errors} check(s) encountered errors{Style.RESET_ALL}")
        
        print("=" * 70 + "\n")
    
    def get_failed_checks(self) -> List[CheckResult]:
        """Get all failed checks."""
        return [r for r in self.results if r.status == "fail"]
    
    def get_warnings(self) -> List[CheckResult]:
        """Get all warnings."""
        return [r for r in self.results if r.status == "warn"]
