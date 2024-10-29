# requirements.txt
Flask==2.3.3
PyGithub==2.1.1
gunicorn==21.2.0
semgrep==1.34.0

# Procfile
web: gunicorn app:app

# runtime.txt
python-3.9.18

# app.json
{
  "name": "github-semgrep-app",
  "description": "GitHub App that runs Semgrep analysis",
  "repository": "https://github.com/yourusername/your-repo-name",
  "keywords": ["python", "github-app", "semgrep"],
  "env": {
    "GITHUB_APP_ID": {
      "description": "GitHub App ID",
      "required": true
    },
    "GITHUB_PRIVATE_KEY": {
      "description": "GitHub App private key",
      "required": true
    },
    "GITHUB_WEBHOOK_SECRET": {
      "description": "GitHub webhook secret",
      "required": true
    }
  }
}