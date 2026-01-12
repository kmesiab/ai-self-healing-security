#!/usr/bin/env python3
"""Parse security scan results and create GitHub issues."""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import requests


class SecurityIssueManager:
    """Manage security issues in GitHub."""

    def __init__(self, token: str, repository: str):
        self.token = token
        self.repository = repository
        self.api_base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def get_existing_issues(self) -> List[Dict]:
        """Get all existing security issues."""
        url = f"{self.api_base}/repos/{self.repository}/issues"
        params = {"state": "all", "labels": "security,automated"}
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    def check_copilot_available(self, username: str) -> bool:
        """Check if user exists and has Copilot access."""
        if not username:
            return False
        url = f"{self.api_base}/users/{username}"
        response = requests.get(url, headers=self.headers)
        return response.status_code == 200

    def create_issue(self, title: str, body: str, assignee: Optional[str] = None) -> Dict:
        """Create a new GitHub issue."""
        url = f"{self.api_base}/repos/{self.repository}/issues"
        data = {
            "title": title,
            "body": body,
            "labels": ["security", "automated"],
        }
        if assignee:
            data["assignees"] = [assignee]
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()

    def close_issue(self, issue_number: int, comment: str):
        """Close an issue with a comment."""
        # Add comment
        comment_url = f"{self.api_base}/repos/{self.repository}/issues/{issue_number}/comments"
        requests.post(comment_url, headers=self.headers, json={"body": comment})

        # Close issue
        issue_url = f"{self.api_base}/repos/{self.repository}/issues/{issue_number}"
        requests.patch(issue_url, headers=self.headers, json={"state": "closed"})


class VulnerabilityParser:
    """Parse vulnerability reports from various scanners."""

    SEVERITY_MAP = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(self, severity_threshold: str):
        self.severity_threshold = severity_threshold
        self.threshold_level = self.SEVERITY_MAP.get(severity_threshold.lower(), 2)

    def parse_safety_json(self, filepath: Path) -> List[Dict]:
        """Parse Safety JSON output."""
        vulnerabilities = []
        try:
            # Check if file is empty or contains non-JSON content
        print(f"DEBUG: Safety file size: {filepath.sstat().st_size} bytes")
        if filepath.stat().st_size == 0:
            reeturn vulnerabilities

            # Read file content to check for JSON
            content = filepath.
                    print(f"DEBUG: Safety file content preview: {content[:200]}")read_text().strip()
            if not content or not content.startswith(('{', '[')):
                print(f"Safety JSON file is empty or not valid JSON, skipping")
                return vulnerabilities

            data = json.loads(content)
            for vuln in data.get("vulnerabilities", []):
                severity = vuln.get("severity", "medium").lower()
                if self.SEVERITY_MAP.get(severity, 0) >= self.threshold_level:
                    vulnerabilities.append({
                        "title": f"[Python] {vuln.get('package_name')}: {vuln.get('advisory')}",
                        "severity": severity,
                        "package": vuln.get("package_name"),
                        "version": vuln.get("analyzed_version"),
                        "description": vuln.get("advisory"),
                        "cve": vuln.get("vulnerability_id"),
                    })
        except Exception as e:
            print(f"Error parsing Safety JSON: {e}")
        return vulnerabilities

    def parse_bandit_json(self, filepath: Path) -> List[Dict]:
        """Parse Bandit JSON output."""
        vulnerabilities = []
        try:
                    print(f"DEBUG: Parsing Bandit file: {filepath}")
            if not filepath.exists() or filepath.stat().st_size == 0:
                return vulnerabilities
            
            with open(filepath) as f:
                data = json.load(f)
                            print(f"DEBUG: Bandit results count: {len(data.get('results', []))}")
            
            for result in data.get("results", []):
                # Map Bandit confidence/severity to our severity
                confidence = result.get("issue_confidence", "MEDIUM")
                severity = "medium"
                if confidence == "HIGH":
                    severity = "high"
                elif confidence == "LOW":
                    severity = "low"
                
                if self.SEVERITY_MAP.get(severity, 0) >= self.threshold_level:
                    vulnerabilities.append({
                        "title": f"[Python/Bandit] {result.get('test_id')}: {result.get('issue_text')}",
                        "severity": severity,
                        "package": "code-analysis",
                        "version": f"Line {result.get('line_number')}",
                        "description": f"{result.get('issue_text')}\n\nFile: {result.get('filename')}\nLine: {result.get('line_number')}",
                        "cve": result.get("test_id"),
                    })
        except Exception as e:
            print(f"Error parsing Bandit JSON: {e}")
        return vulnerabilities

    def parse_npm_audit_json(self, filepath: Path) -> List[Dict]:
        """Parse npm audit JSON output."""
        vulnerabilities = []
        try:
            if not filepath.exists() or filepath.stat().st_size == 0:
                return vulnerabilities
                
            with open(filepath) as f:
                data = json.load(f)
                
            for vuln_id, vuln in data.get("vulnerabilities", {}).items():
                severity = vuln.get("severity", "medium").lower()
                if self.SEVERITY_MAP.get(severity, 0) >= self.threshold_level:
                    vulnerabilities.append({
                        "title": f"[JavaScript] {vuln.get('name')}: {vuln.get('title', 'Security vulnerability')}",
                        "severity": severity,
                        "package": vuln.get("name"),
                        "version": vuln.get("range"),
                        "description": vuln.get("overview", ""),
                        "cve": vuln.get("cves", [None])[0] if vuln.get("cves") else None,
                    })
        except Exception as e:
            print(f"Error parsing npm audit JSON: {e}")
        return vulnerabilities

    def parse_all_results(self, results_dir: Path) -> List[Dict]:
        """Parse all result files in directory."""
        all_vulnerabilities = []
        
        # Parse Safety results (Python)
        safety_file = results_dir / "safety.json"
        if safety_file.exists():
            all_vulnerabilities.extend(self.parse_safety_json(safety_file))
        
        # Parse Bandit results (Python)
        bandit_file = results_dir / "bandit.json"
        if bandit_file.exists():
            all_vulnerabilities.extend(self.parse_bandit_json(bandit_file))
        
        # Parse npm audit results (JavaScript)
        npm_file = results_dir / "npm-audit.json"
        if npm_file.exists():
            all_vulnerabilities.extend(self.parse_npm_audit_json(npm_file))
        
        return all_vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="Parse scan results and create issues")
    parser.add_argument("--results-dir", required=True, help="Directory with scan results")
    parser.add_argument("--severity-threshold", default="medium", help="Minimum severity")
    parser.add_argument("--copilot-assignee", default="", help="Copilot user to assign")
    parser.add_argument("--fallback-assignee", default="", help="Fallback assignee")
    parser.add_argument("--auto-close-fixed", default="true", help="Auto-close fixed issues")
    parser.add_argument("--repository", required=True, help="Repository (owner/repo)")
    args = parser.parse_args()

    # Initialize managers
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: GITHUB_TOKEN environment variable not set")
        sys.exit(1)

    issue_manager = SecurityIssueManager(github_token, args.repository)
    parser_obj = VulnerabilityParser(args.severity_threshold)

    # Parse all vulnerabilities
    results_dir = Path(args.results_dir)
    vulnerabilities = parser_obj.parse_all_results(results_dir)
    print(f"Found {len(vulnerabilities)} vulnerabilities")

    # Determine assignee
    assignee = None
    if args.copilot_assignee:
        if issue_manager.check_copilot_available(args.copilot_assignee):
            assignee = args.copilot_assignee
            print(f"Assigning to Copilot user: {assignee}")
        elif args.fallback_assignee:
            assignee = args.fallback_assignee
            print(f"Copilot user not available, using fallback: {assignee}")

    # Create issues for new vulnerabilities
    existing_issues = issue_manager.get_existing_issues()
    existing_titles = {issue["title"] for issue in existing_issues}
    issues_created = 0

    for vuln in vulnerabilities:
        if vuln["title"] not in existing_titles:
            body = f"""## Security Vulnerability Detected

**Severity:** {vuln['severity'].upper()}
**Package:** {vuln['package']}
**Version:** {vuln['version']}

### Description

{vuln['description']}

{f"**CVE:** {vuln['cve']}" if vuln.get('cve') else ""}

---
*This issue was automatically created by the AI Self-Healing Security Scanner.*
"""
            issue_manager.create_issue(vuln["title"], body, assignee)
            issues_created += 1
            print(f"Created issue: {vuln['title']}")

    # Generate summary
    highest_severity = max((v["severity"] for v in vulnerabilities), default="low")
    summary = {
        "vulnerabilities_found": len(vulnerabilities),
        "issues_created": issues_created,
        "highest_severity": highest_severity,
    }

    # Write summary
    summary_file = results_dir / "summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Set GitHub Action outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"vulnerabilities-found={len(vulnerabilities)}\n")
            f.write(f"issues-created={issues_created}\n")
            f.write(f"highest-severity={highest_severity}\n")

    print(f"\nSummary: {issues_created} issues created, {len(vulnerabilities)} total vulnerabilities")


if __name__ == "__main__":
    main()
