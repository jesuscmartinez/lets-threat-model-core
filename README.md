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
 git clone https://github.com/jesuscmartinez/lets-threat-model-core
 cd lets-threat-model-core
```

### **2. Install Dependencies**
Ensure you have Python **3.8+** installed, then install dependencies:
```sh
pip install -r requirements.txt
```

### **3. Set Up Environment Variables**
Create a `.env` file and define necessary environment variables:
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
# OPENAI Configuration
# ----------------------------
OPENAI_API_KEY=api_key

# ----------------------------
# ANTHROPIC Configuration
# ----------------------------
ANTHROPIC_API_KEY=api_key
```

---

## 📄 Usage
### **1. Prepare a YAML File**
Create a YAML file with the asset, repositories and config settings. Example:
```yaml
asset:
  name: "OWASP Juice Shop"
  description: "An intentionally insecure web application for security training."
  internet_facing: true
  authn_type: "Password"
  data_classification: "CONFIDENTIAL"

repositories:
  - name: "Juice Shop" 
    url: "github.com/juice-shop/juice-shop"

# ----------------------------
# Configuration
# ----------------------------
config:
  llm_provider: "openai"
  context_window: 128000
  max_output_tokens: 16384
  categorization_agent_llm: "gpt-4o-mini" # simple task for categorizing files for review
  review_agent_llm: "o1-mini" # reasoning task of building Data Flow Report
  threat_model_agent_llm: "o1-mini" # reasoning task of assessing Data Flow Report and identifing Threats
  report_agent_llm: "gpt-4o-mini" # simple task to help generate report text
```
Field Descriptions
	•	asset: Details of the asset to be analyzed. ￼
    •	name: Name of the asset.
    •	description: Brief description of the asset.
    •	internet_facing: Indicates if the asset is exposed to the internet (true or false).
    •	authn_type: Authentication type used by the asset (e.g., NONE, BASIC, OAUTH).
    •	data_classification: Classification of data handled by the asset (e.g., PUBLIC, INTERNAL, CONFIDENTIAL).
	•	repositories: List of repositories associated with the asset.
    •	name: Name of the repository.
    •	url: URL of the repository.
	•	config: Configuration settings for the threat modeling process. ￼
    •	llm_provider: Provider of the language model (e.g., openai).
    •	categorization_agent_llm: Language model used for categorization.
    •	review_agent_llm: Language model used for review.
    •	threat_model_agent_llm: Language model used for threat modeling.
    •	report_agent_llm: Language model used for report generation.
    •	context_window: Context window size for the language model.
    •	max_output_tokens: Maximum number of tokens for the output.
    •	review_max_file_in_batch: Maximum number of files to review in a batch.
    •	review_token_buffer: Token buffer ratio for review.
    •	categorize_max_file_in_batch: Maximum number of files to categorize in a batch.
    •	categorize_token_buffer: Token buffer ratio for categorization.
    •	categorize_only: Flag to indicate if only categorization should be performed (true or false).
    •	completion_threshold: Threshold for completion.
  •	exclude_patterns: List of file patterns to exclude from analysis.
  •	include_patterns: List of file patterns to include in the analysis.


### **2. Run the Script**
Execute the script using the following command:
```sh
python main.py config.yaml
```

**Optional:** Specify an output file:
```sh
python main.py config.yaml -o output_report.md
```

### **3. Run the Script via Docker**
#### **Build the Docker Image**
```sh
docker build -t threat_model_generator -f cli/Dockerfile . 
```

#### **Run the Container**
```sh
docker run --rm -it -v $(pwd)/cli_data:/app/data --env-file cli/.env threat_model_generator python main.py data/config.yaml -o data/threat_model_report.md
```

#### **Access the Generated Report**
The Markdown report will be available in the `cli_data/` directory on your host machine:
```sh
cat cli_data/threat_model_report.md
```

---
## Example Output:
### JuiceShop
Here is an example output when using GPT 4o-mini on OWASP Juiceshop

Initial data flow report...
![Juiceshop initial steps...](demo/initial_data_flow.png)

Threats...
![Juiceshop threats...](demo/threats.png)

Data Flow Diagram
![Juiceshop DFD](demo/juiceshop_gpt4omini_dfd.png)

Threat Model Report...

[Threat Model Report w/ o1-mini](demo/juiceshop_report_o1mini.md)

[Threat Model Report w/ gpt-4o-mini](demo/juiceshop_report_gpt4omini.md)

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

