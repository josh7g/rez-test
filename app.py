from flask import Flask, request, jsonify
import hmac
import hashlib
import os
import json
import subprocess
from github import Github
from github import GithubIntegration

app = Flask(__name__)

# GitHub App credentials
GITHUB_APP_ID = os.environ.get('GITHUB_APP_ID')
GITHUB_PRIVATE_KEY = os.environ.get('GITHUB_PRIVATE_KEY')
GITHUB_WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')

def verify_webhook_signature(request_body, signature_header):
    """Verify that the webhook signature is valid"""
    expected_signature = 'sha256=' + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        request_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def get_github_client(installation_id):
    """Get an authenticated GitHub client for the installation"""
    git_integration = GithubIntegration(
        GITHUB_APP_ID,
        GITHUB_PRIVATE_KEY
    )
    access_token = git_integration.get_access_token(installation_id).token
    return Github(access_token)

def run_semgrep_analysis(repo_url, branch='main'):
    """Run Semgrep analysis on the repository"""
    # Clone the repository
    clone_cmd = f'git clone --depth 1 -b {branch} {repo_url} temp_repo'
    subprocess.run(clone_cmd, shell=True)
    
    # Run Semgrep
    semgrep_cmd = 'semgrep scan --config auto --json temp_repo'
    result = subprocess.run(semgrep_cmd, shell=True, capture_output=True, text=True)
    
    # Clean up
    subprocess.run('rm -rf temp_repo', shell=True)
    
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "Failed to parse Semgrep output"}

@app.route('/webhook', methods=['POST'])
def webhook():
    # Verify webhook signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_webhook_signature(request.get_data(), signature):
        return jsonify({'error': 'Invalid signature'}), 401

    event = request.headers.get('X-GitHub-Event')
    payload = request.json

    if event == 'installation' and payload['action'] == 'created':
        # Get repository information
        installation_id = payload['installation']['id']
        repositories = payload['repositories']

        g = get_github_client(installation_id)
        results = {}

        for repo in repositories:
            repo_name = repo['full_name']
            repo_obj = g.get_repo(repo_name)
            repo_url = f"https://x-access-token:{g.get_installation(installation_id).token}@github.com/{repo_name}.git"
            
            # Run Semgrep analysis
            semgrep_results = run_semgrep_analysis(repo_url)
            results[repo_name] = semgrep_results

            # Create an issue with the results
            if not isinstance(semgrep_results, dict) or 'error' not in semgrep_results:
                issue_title = "Semgrep Security Analysis Results"
                issue_body = f"```json\n{json.dumps(semgrep_results, indent=2)}\n```"
                repo_obj.create_issue(title=issue_title, body=issue_body)

        return jsonify(results)

    return jsonify({'status': 'ignored event'})

if __name__ == '__main__':
    app.run(port=3000)