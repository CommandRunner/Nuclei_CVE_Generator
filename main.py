from flask import Flask, request, jsonify
import boto3
import base64
import json
import os
import re
import requests

app = Flask(__name__)

bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')


def fetch_exploitdb(cve_id):
    """Search Exploit-DB for exploits matching the CVE ID."""
    # Exploit-DB search expects just the numeric part e.g. 2021-44228
    cve_num = cve_id[4:]  # strip 'CVE-'

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest'
    }

    try:
        response = requests.get(
            'https://www.exploit-db.com/search',
            params={
                'cve': cve_num,
                'draw': '1',
                'start': '0',
                'length': '5'
            },
            headers=headers,
            timeout=15
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[Exploit-DB] Search failed for {cve_id}: {e}")
        return []

    exploits = []
    for item in data.get('data', [])[:3]:
        exploit_id = item.get('id')
        if not exploit_id:
            continue
        raw = _fetch_exploitdb_raw(exploit_id)
        exploits.append({
            'id': exploit_id,
            'title': item.get('code', ''),
            'type': item.get('type', {}).get('label', '') if isinstance(item.get('type'), dict) else item.get('type', ''),
            'platform': item.get('platform', {}).get('label', '') if isinstance(item.get('platform'), dict) else item.get('platform', ''),
            'date': item.get('date_published', ''),
            'url': f'https://www.exploit-db.com/exploits/{exploit_id}',
            'content': raw
        })

    return exploits


def _fetch_exploitdb_raw(exploit_id):
    """Fetch raw exploit file content from Exploit-DB."""
    try:
        response = requests.get(
            f'https://www.exploit-db.com/raw/{exploit_id}',
            timeout=10
        )
        if response.status_code == 200:
            return response.text[:3000]
    except Exception as e:
        print(f"[Exploit-DB] Failed to fetch raw exploit {exploit_id}: {e}")
    return ''


def fetch_github_pocs(cve_id):
    """Search GitHub for PoC repositories related to the CVE."""
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }
    if GITHUB_TOKEN:
        headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'

    results = []

    try:
        response = requests.get(
            'https://api.github.com/search/repositories',
            params={
                'q': f'{cve_id} poc',
                'sort': 'stars',
                'order': 'desc',
                'per_page': 5
            },
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        items = response.json().get('items', [])
    except Exception as e:
        print(f"[GitHub] Search failed for {cve_id}: {e}")
        return []

    for repo in items[:3]:
        readme = _fetch_github_readme(repo.get('full_name', ''), headers)
        results.append({
            'name': repo.get('full_name'),
            'url': repo.get('html_url'),
            'description': repo.get('description') or '',
            'stars': repo.get('stargazers_count', 0),
            'readme': readme
        })

    return results


def _fetch_github_readme(repo_full_name, headers):
    """Fetch and decode a GitHub repo's README."""
    if not repo_full_name:
        return ''
    try:
        response = requests.get(
            f'https://api.github.com/repos/{repo_full_name}/readme',
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            encoded = response.json().get('content', '')
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            return decoded[:2000]
    except Exception as e:
        print(f"[GitHub] Failed to fetch README for {repo_full_name}: {e}")
    return ''


def build_prompt(cve_id, exploits, github_pocs):
    """Build the prompt for Bedrock using PoC data from Exploit-DB and GitHub."""

    exploit_section = ''
    if exploits:
        for i, e in enumerate(exploits, 1):
            exploit_section += f"""
Exploit {i}:
  Title: {e['title']}
  Type: {e['type']}
  Platform: {e['platform']}
  URL: {e['url']}
  Code:
{e['content']}
"""
    else:
        exploit_section = 'No Exploit-DB entries found.'

    github_section = ''
    if github_pocs:
        for i, repo in enumerate(github_pocs, 1):
            github_section += f"""
Repository {i}: {repo['name']} ({repo['stars']} stars)
  URL: {repo['url']}
  Description: {repo['description']}
  README:
{repo['readme']}
"""
    else:
        github_section = 'No GitHub PoC repositories found.'

    return f"""You are a cybersecurity expert specializing in creating Nuclei templates.

Your task is to create a Nuclei detection template for {cve_id} based on the following real-world PoC data.

---
EXPLOIT-DB DATA:
{exploit_section}

---
GITHUB POC DATA:
{github_section}

---
Using the above PoC information, create a valid Nuclei YAML template that:
1. Accurately detects the vulnerability described in the PoC material
2. Uses the correct HTTP method, endpoint, headers, and payload derived from the PoCs
3. Includes matchers based on actual response indicators shown in the PoC (status codes, response body strings, headers)
4. Has complete metadata: id, name, author, severity, description, reference, tags, cve-id
5. Sets severity based on the nature of the vulnerability (critical/high/medium/low)
6. Includes the Exploit-DB and GitHub URLs in the references
7. Tags include: cve, {cve_id.lower()}, and relevant technology tags based on the affected platform

Return ONLY the YAML template. No explanations, no markdown code fences.
"""


def call_bedrock(prompt):
    response = bedrock.invoke_model(
        modelId="anthropic.claude-3-5-haiku-20241022-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4096,
            "temperature": 0.2
        })
    )
    result = json.loads(response['body'].read())
    return result['content'][0]['text']


@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    cve_id = (data.get('cve_id') or data.get('id') or '').strip().upper()

    if not cve_id:
        return jsonify({"error": "Missing CVE ID"}), 400

    if not CVE_ID_PATTERN.match(cve_id):
        return jsonify({"error": "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN"}), 400

    exploits = fetch_exploitdb(cve_id)
    github_pocs = fetch_github_pocs(cve_id)

    if not exploits and not github_pocs:
        return jsonify({"error": f"No PoC data found for {cve_id} on Exploit-DB or GitHub"}), 404

    try:
        prompt = build_prompt(cve_id, exploits, github_pocs)
        template = call_bedrock(prompt)

        return jsonify({
            "template": template,
            "sources": {
                "exploitdb": [{"id": e['id'], "title": e['title'], "url": e['url']} for e in exploits],
                "github": [{"repo": g['name'], "stars": g['stars'], "url": g['url']} for g in github_pocs]
            }
        })
    except Exception as e:
        print(f"Error generating template for {cve_id}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})


if __name__ == '__main__':
    app.run(port=5000, debug=True)
