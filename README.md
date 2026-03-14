# Nuclei CVE Generator

A Flask API that automatically generates [Nuclei](https://github.com/projectdiscovery/nuclei) templates for CVEs using AWS Bedrock (Claude) and data from the NIST NVD API.

---

## How It Works

1. You send a CVE ID to the `/generate` endpoint
2. It fetches the CVE details from the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
3. It builds a structured prompt with the CVE metadata (CVSS score, CWE, affected products, references)
4. It sends the prompt to Claude via AWS Bedrock
5. Returns a ready-to-use Nuclei YAML template

---

## Deploying on AWS EC2

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

Once the instance is running, connect via SSH:

```bash
ssh -i /path/to/your-key.pem ubuntu@<your-ec2-public-ip>
```

If you get a permissions error on the key:
```bash
chmod 400 /path/to/your-key.pem
```

---

### 5. Set Up the Environment

Once connected, run the following:

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

Since the EC2 instance has the IAM role attached, you don't need to run `aws configure` or store any credentials. Verify it's working:

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

Test it from your local machine:

```bash
curl -X POST http://<your-ec2-public-ip>:5000/generate \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2021-44228"}'
```

---

### 8. Run as a Background Service (Optional)

If you want the server to keep running after you disconnect, set it up as a systemd service:

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

To view logs:
```bash
journalctl -u nuclei-cve -f
```

---

## Local Usage

**Requirements:**
- Python 3.9+
- AWS account with Bedrock access (Claude model enabled in `us-east-1`)
- AWS credentials configured (`~/.aws/credentials` or environment variables)

```bash
git clone https://github.com/CommandRunner/Nuclei_CVE_Generator
cd Nuclei_CVE_Generator
pip install -r requirements.txt
aws configure  # enter your AWS access key, secret, and region (us-east-1)
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
  "cve_info": {
    "id": "CVE-2021-44228",
    "description": "...",
    "cvss_v3": { "score": 10.0, "severity": "CRITICAL", "vector": "..." }
  }
}
```

**Health check:**
```bash
curl http://localhost:5000/health
```

---

## Security Notice

- Use only on authorized targets.
- Generated templates are AI-produced — always review before running against production systems.
- If exposing port 5000 publicly, consider putting it behind a reverse proxy (nginx) with authentication.
