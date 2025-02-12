# Lets Threat Model
Agentic AI Threat Modeling

This script generates a **threat model report** in **Markdown format** from a provided YAML file that defines an asset and its associated repositories.

## 📌 Features
- Parses a **YAML configuration file** containing asset and repository details.
- Generates a **threat model** based on the given data.
- Saves the output as a **Markdown report**.
- Provides **logging and error handling** for a smooth execution.

---

## 🚀 Installation
### **1. Clone the Repository**
```sh
 git clone https://github.com/your-repo/threat-model-generator.git
 cd threat-model-generator
```

### **2. Install Dependencies**
Ensure you have Python **3.8+** installed, then install dependencies:
```sh
pip install -r requirements.txt
```

### **3. Set Up Environment Variables**
Create a `.env` file and define necessary environment variables (optional):
```ini
# ----------------------
# GLOBAL Configuration
# ----------------------
LOG_LEVEL=INFO

# ----------------------------
# GITHUB Configuration
# ----------------------------
USERNAME=username
PAT=personal_access_token


# ----------------------------
# Agent Configuration
# ----------------------------
DATA_FLOW_AGENT_LLM=gpt-4o-mini
THREAT_MODEL_AGENT_LLM=gpt-4o-mini
REPORT_AGENT_LLM=gpt-4o-mini

# ----------------------------
# OPENAI Configuration
# ----------------------------
OPENAI_API_KEY=api_key
CONTEXT_WINDOW=128000

# ----------------------------
# ANTHROPIC Configuration
# ----------------------------
ANTHROPIC_API_KEY=api_key
```

---

## 📄 Usage
### **1. Prepare a YAML File**
Create a YAML file with the asset and repositories information. Example:
```yaml
asset:
  name: "Test Asset"
  description: "Testing local threat model generation"
  internet_facing: true
  authn_type: "NONE"
  data_classification: "PUBLIC"

repositories:
  - name: "Test Repo 1"
    url: "https://github.com/user/repo1.git"
  - name: "Test Repo 2"
    url: "https://github.com/user/repo2.git"
```

### **2. Run the Script**
Execute the script using the following command:
```sh
python main.py input_data.yaml
```

**Optional:** Specify an output file:
```sh
python main.py input_data.yaml -o my_report.md
```

### **3. Run the Script via Docker**
#### **Build the Docker Image**
```sh
docker build -t threat_model_generator -f cli/Dockerfile . 
```

#### **Run the Container**
```sh
docker run --rm -it -v $(pwd)/cli_data:/app/data --env-file cli/.env threat_model_generator python main.py data/input_data.yaml -o data/threat_model_report.md
```

#### **Access the Generated Report**
The Markdown report will be available in the `cli_data/` directory on your host machine:
```sh
cat cli_data/threat_model_report.md
```

---

## 🛠 Development & Debugging
### **Run with Debug Logging**
To enable detailed logging, set `LOG_LEVEL` to `DEBUG`:
```sh
export LOG_LEVEL=DEBUG
python main.py input_data.yaml
```

### **Run with a Virtual Environment**
```sh
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
pip install -r requirements.txt
```

---

## 🏗 Contributing
Feel free to submit **issues** or **pull requests** to improve the the project.

---

