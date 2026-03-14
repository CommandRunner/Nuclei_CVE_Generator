# Nuclei CVE Generator

A Flask API that automatically generates [Nuclei](https://github.com/projectdiscovery/nuclei) templates for CVEs using real-world PoC data from Exploit-DB and GitHub, powered by Claude AI.

---

## How It Works

1. You send a CVE ID to the `/generate` endpoint
2. It searches **Exploit-DB** for matching exploits and fetches the raw exploit code
3. It searches **GitHub** for PoC repositories and fetches their README content
4. It builds a prompt from the real PoC data (HTTP requests, payloads, reproduction steps)
5. It sends the prompt to Claude and returns a ready-to-use Nuclei YAML template

---

## Setup Options

- **Option A — AWS Bedrock on EC2** (no API key needed, uses IAM roles)
- **Option B — Anthropic API locally** (simpler, just needs an API key)

---

## Option A: Deploying on AWS EC2

### 1. Enable Bedrock Model Access

Before launching anything, make sure the Claude model is enabled in your AWS account:

1. Go to the [AWS Bedrock console](https://console.aws.amazon.com/bedrock/home?region=us-east-1#/modelaccess)
2. Click **Modify model access**
3. Find **Claude 3.5 Haiku** under Anthropic and enable it
4. Wait for status to show **Access granted** (usually instant)

---

### 2. Create an IAM Role for EC2

Your EC2 instance needs permission to call Bedrock. The safest way is an IAM role — no hardcoded credentials needed.

1. Go to **IAM → Roles → Create role**
2. Select **AWS service** → **EC2** → Next
3. Search for and attach the policy **AmazonBedrockFullAccess** (or create a custom policy scoped to just `bedrock:InvokeModel`)
4. Name the role something like `nuclei-cve-bedrock-role` and create it

---

### 3. Launch an EC2 Instance

1. Go to **EC2 → Launch Instance**
2. Choose **Ubuntu Server 24.04 LTS** (free tier eligible)
3. Instance type: **t2.micro** is fine for personal use, **t3.small** if you expect heavier load
4. **Key pair**: create or select an existing one — you'll need this to SSH in
5. **Network settings**:
   - Allow **SSH (port 22)** from your IP
   - Add a custom TCP rule for **port 5000** from your IP (or `0.0.0.0/0` if you want it publicly accessible)
6. Under **Advanced details → IAM instance profile**: select the role you created in step 2
7. Launch the instance

---

### 4. Connect to the Instance

```bash
ssh -i /path/to/your-key.pem ubuntu@<your-ec2-public-ip>
```

If you get a permissions error on the key:
```bash
chmod 400 /path/to/your-key.pem
```

---

### 5. Set Up the Environment

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv git -y

# Clone the repo
git clone https://github.com/CommandRunner/Nuclei_CVE_Generator
cd Nuclei_CVE_Generator

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

### 6. Verify AWS Access

Since the EC2 instance has the IAM role attached, you don't need to store any credentials. Verify it's working:

```bash
sudo apt install awscli -y
aws sts get-caller-identity
```

You should see your account ID and the role ARN. If this works, Bedrock calls will work too.

---

### 7. Run the Server

```bash
python main.py
```

The API will be available at `http://<your-ec2-public-ip>:5000`.

---

### 8. Run as a Background Service (Optional)

```bash
sudo nano /etc/systemd/system/nuclei-cve.service
```

Paste the following (adjust paths if needed):

```ini
[Unit]
Description=Nuclei CVE Generator
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/Nuclei_CVE_Generator
ExecStart=/home/ubuntu/Nuclei_CVE_Generator/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable nuclei-cve
sudo systemctl start nuclei-cve
sudo systemctl status nuclei-cve
```

View logs:
```bash
journalctl -u nuclei-cve -f
```

---

## Option B: Running Locally with the Anthropic API (No AWS Required)

If you don't want to set up AWS, you can swap Bedrock for the Anthropic API directly.

### 1. Get an Anthropic API Key

Sign up at [console.anthropic.com](https://console.anthropic.com) and create an API key.

---

### 2. Install the Anthropic SDK

```bash
pip install anthropic
```

Or add it to `requirements.txt`:
```
anthropic>=0.25.0
```

---

### 3. Modify `main.py`

Replace the `call_bedrock` function with the following:

```python
import anthropic

anthropic_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def call_bedrock(prompt):
    message = anthropic_client.messages.create(
        model="claude-3-5-haiku-20241022",
        max_tokens=4096,
        temperature=0.2,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text
```

You can remove the `boto3` import and the `bedrock` client at the top of the file since they're no longer needed.

---

### 4. Set Your API Key and Run

```bash
git clone https://github.com/CommandRunner/Nuclei_CVE_Generator
cd Nuclei_CVE_Generator
pip install -r requirements.txt anthropic
export ANTHROPIC_API_KEY=your_api_key_here
python main.py
```

---

## Usage

**Generate a template:**
```bash
curl -X POST http://localhost:5000/generate \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2021-44228"}'
```

**Response:**
```json
{
  "template": "id: CVE-2021-44228\ninfo:\n  name: ...",
  "sources": {
    "exploitdb": [{"id": "...", "title": "...", "url": "..."}],
    "github": [{"repo": "...", "stars": 100, "url": "..."}]
  }
}
```

**Increase GitHub API rate limit (optional):**
```bash
export GITHUB_TOKEN=your_github_token
```
Without a token: 10 requests/min. With a token: 30 requests/min.

**Health check:**
```bash
curl http://localhost:5000/health
```

---

## Security Notice

- Use only on authorized targets.
- Generated templates are AI-produced — always review before running against production systems.
- If exposing port 5000 publicly, consider putting it behind a reverse proxy (nginx) with authentication.
