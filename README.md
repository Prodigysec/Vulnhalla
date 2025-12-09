# Vulnhalla 
# Automated CodeQL Analysis with LLM Classification

<div align="center">
  <img src="images/vulnhalla_logo.png" alt="Vulnhalla" width="400">
</div>

Vulnhalla automates the complete security analysis pipeline:

1. **Fetching repositories** of a given programming language from GitHub
2. **Downloading** their corresponding [CodeQL](https://github.com/github/codeql) databases (if available)
3. **Running CodeQL queries** on those databases to detect security or code-quality issues
4. **Post-processing** the results with an LLM (ChatGPT, Claude, etc.) to classify and filter issues

---

### Key Modules

- **`src/codeql/fetch_repos.py`**: Fetches GitHub repositories and downloads their CodeQL databases. Creates `output/zip_dbs` and `output/databases/<lang>/<org>/<repo>` folders.

- **`src/codeql/run_codeql_queries.py`**: Pre-compiles `.ql` queries in `data/queries/<LANG>/tools` and `data/queries/<LANG>/issues`, then analyzes databases in `output/databases/<LANG>/`. Outputs `issues.csv` per database.

- **`src/llm/llm_analyzer.py`**: Handles communication with LLMs (OpenAI, Azure, Gemini, etc.) to classify results. Includes prompt templates and API logic.

- **`src/vulnhalla.py`**: Main orchestrator that aggregates results and uses LLM for classification. Organizes outputs by type/severity and stores in `output/results/<LANG>/<ISSUE_TYPE>/`.

- **`src/ui/ui_app.py`**: User Interface (UI) for browsing and exploring analysis results with interactive features.

- **`src/pipeline.py`**: Unified pipeline orchestrator that runs the complete workflow (fetch, query, classify, UI) in a single command.

---

## 🚀 Quick Start

### Step 1: Prerequisites

Before starting, ensure you have:

- **Python 3.10 – 3.13** (Python 3.11 or 3.12 recommended)
  - Python 3.14+ is not supported (this tool needs grpcio which is not supported by Python 3.14+)
  - Download from [python.org](https://www.python.org/downloads/)

- **CodeQL CLI**
  - Download from [CodeQL CLI releases](https://github.com/github/codeql-cli-binaries/releases)
  - Make sure `codeql` is in your PATH, or you'll set the path in `.env` (see Step 2)

- **(Optional) GitHub API token**
  - For higher rate limits when downloading databases
  - Get from [GitHub Settings > Tokens](https://github.com/settings/tokens)

- **LLM API key**
  - OpenAI, Azure, or Gemini API key (depending on your provider)

### Step 2: Configure Environment

All configuration is in a single file: `.env`

1. **Clone the repository:**
```bash
git clone https://github.com/cyberark/Vulnhalla
cd Vulnhalla
```

2. **Copy `.env.example` to `.env`:**
```bash
cp .env.example .env
```

3. **Edit `.env` and fill in your values:**

**Example for OpenAI:**
```env
CODEQL_PATH=codeql
GITHUB_TOKEN=ghp_your_token_here
PROVIDER=openai
MODEL=gpt-4o
OPENAI_API_KEY=your-api-key-here
```

**Optional parameters** (with defaults - recommended to leave as-is):

> **Note:** Do not increase these values unless you fully understand the impact. Lower values keep the model stable and deterministic, which is critical for security analysis. Higher values may cause the model to become inconsistent, creative, or hallucinate results.

```env
LLM_TEMPERATURE=0.2
LLM_TOP_P=0.2
```

**Optional:** Create a virtual environment:

```bash
# (Optional) Create virtual environment
python3 -m venv venv
venv\Scripts\activate # On Windows
# On MacOS/Linux: source venv/bin/activate
```

### Step 3: setup

**Option 1: Automated Setup (Recommended)**

```bash
python setup.py
```

**Note:** Virtual environment is optional. If `venv/` exists, setup will use it. Otherwise, it installs to your current Python environment.

The setup script will:
- Install Python dependencies
if dependencies are already installed (skips if found)
- Install Python dependencies from `requirements.txt`
- Initialize CodeQL packs

**Note:** If a `venv/` directory exists, setup will use it. Otherwise, it installs to your current Python environment.

**Option 2: Manual Setup**

If you prefer to install manually:

### Install dependencies
```bash
pip install -r requirements.txt
```

### Initialize CodeQL packs
```bash
cd data/queries/cpp/tools
codeql pack install
cd ../issues
codeql pack install
cd ../../../..
```

### Step 4: Run the Pipeline

**Option 1: Using the Unified Pipeline**

Run the complete pipeline with a single command:

```bash
# Analyze a specific repository
python src/pipeline.py redis/redis

# Analyze top 100 repositories
python src/pipeline.py
```

This will automatically:
1. Fetch CodeQL databases
2. Run CodeQL queries on all downloaded databases
3. Analyze results with LLM and save to `output/results/`
4. Open the UI to browse results

**Option 2: Using the Example Script**

Run the end-to-end example:

```bash
python examples/example.py
```

This will:
1. Fetch CodeQL databases for `videolan/vlc` and `redis/redis`
2. Run CodeQL queries on all downloaded databases
3. Analyze results with LLM and save to `output/results/`

---

## 🖥️ User Interface (UI)

Vulnhalla includes a full-featured User Interface for browsing and exploring analysis results.

### Running the UI

```bash
python src/ui/ui_app.py
# or
python examples/ui_example.py
```

### UI Layout

The UI displays a two-panel top area with a controls bar at the bottom:

**Top Area (side-by-side, resizable):**

- **Left Panel (Issues List):**
  - DataTable showing: **ID**, **Repo**, **Issue Name**, **File**, **LLM decision**, **Manual decision**
  - Issues count and sort indicator
  - Search input box at the bottom, updates as you type (case-insensitive).

- **Right Panel (Details):**
  - **LLM decision Section**: Shows the LLM's classification (True Positive, False Positive, or Needs More Data)
  - **Metadata Section**: Issue name, Repo, File, Line, Type, Function name
  - **Code Section**: 
    - 📌 Initial Code Context (first code snippet the LLM saw)
    - 📥 Additional Code (code that the LLM requested during the conversation) - only shown if additional code exists
    - Vulnerable line highlighted in red
  - **Summary Section**: LLM final answer/decision
  - **Manual Decision Select**: Dropdown at the bottom to set manual verdict (True Positive, False Positive, Uncertain, or Not Set)

**Bottom Controls Bar:**

- Language: C (only language currently supported)
- Filter by llm desicion dropdown: All, True Positive, False Positive, Needs more Info to decide
- Action buttons: Refresh, Run Analysis
- Key bindings help text

### Key Bindings

- `↑`/`↓` - Navigate issue list (row-by-row)
- `Tab` / `Shift+Tab` - Switch focus between panels
- `Enter` - Show details for selected issue
- `/` - Focus search input box (in left panel)
- `Esc` - Clear search and return focus to issues table
- `r` - Reload results from disk
- `[` / `]` - Resize left/right panels (adjust split position)
- `q` - Quit application

### Interactive Features

#### Column Sorting

- **Click any column header** to sort by that column
- Default sorting: by Repo (ascending), then by ID (ascending)

#### Resizable Panels

- **Draggable divider** between Issues List and Details panels
- **Mouse**: Click and drag the divider to resize
- **Keyboard**: Use `[` to move divider left, `]` to move divider right
- Split position is remembered during the session

---

## 📊 Output Structure

After running the pipeline, results are organized in `output/results/<LANG>/<ISSUE_TYPE>/`:

```
output/results/c/Copy_function_using_source_size/
├── 1_raw.json      # Original CodeQL issue data
├── 1_final.json    # LLM conversation and classification
├── 2_raw.json
├── 2_final.json
└── ...
```

Each `*_final.json` contains:
- Full LLM conversation (system prompts, user messages, assistant responses, tool calls)
- Final status code (1337 = vulnerable, 1007 = secure, 7331/3713 = needs more info)

Each `*_raw.json` contains:
- Original CodeQL issue data
- Function context
- Database path (includes org/repo information: `output/databases/<LANG>/<ORG>/<REPO>`)
- Issue location

---

## 🛠 Troubleshooting

- **CodeQL CLI not found**:  
  Set `CODEQL_PATH` in your `.env` file to the full path of your CodeQL executable.
  **On Windows**: The path must end with `.cmd` (e.g., `C:\path\to\codeql\codeql.cmd`).

- **GitHub rate limits**:  
  Set `GITHUB_TOKEN` in your `.env` file (get token from https://github.com/settings/tokens).

- **LLM issues**:  
  Check your API keys in `.env` file match your selected provider.

- **Import errors in UI**:  
  Make sure you're running from the project root directory, or use `python examples/ui_example.py` which handles path setup.

---

## 📝 Status Codes

The LLM uses the following status codes:

- **1337**: Security vulnerability found (True Positive)
- **1007**: Code is secure, no vulnerability (False Positive)
- **7331**: More code/information needed to validate security
- **3713**: Likely not a security problem, but more info needed (used with 7331)

The UI maps these to:
- `1337` → "True Positive"
- `1007` → "False Positive"
- `7331` or `3713` → "Needs More Data"

---

## 🔧 Development

### Project Dependencies

See `requirements.txt` for Python dependencies:
- `requests` - HTTP requests for GitHub API
- `pySmartDL` - Smart download manager for CodeQL databases
- `litellm` - Unified LLM interface supporting multiple providers
- `python-dotenv` - Environment variable management
- `PyYAML` - YAML parsing for CodeQL pack files
- `textual` - Terminal UI framework

### CodeQL Queries

CodeQL queries are organized in `data/queries/<LANG>/`:
- `issues/` - Security issue detection queries
- `tools/` - Helper queries (function trees, classes, global variables, macros)

Each directory contains a `qlpack.yml` file defining the CodeQL pack.

---

## 📄 License

Copyright (c) 2025 CyberArk Software Ltd. All rights reserved.

This repository is licensed under the Apache License, Version 2.0 - see [LICENSE.txt](LICENSE.txt) for more details.

---

## 🤝 Contributing


We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing guide](https://github.com/cyberark/Vulnhalla/blob/main/CONTRIBUTING.md).

---  
### Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for all contributors.

---

## 📧 Contact

Feel free to contact us via GitHub issues if you have any feature requests or project issues.
