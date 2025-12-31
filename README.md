# scan4domain

A Python tool for generating domain combinations and checking domain registration status.

## Features

- **Domain Generator** (`generate.py`): Generate all possible domain combinations based on a template pattern
- **Domain Checker** (`main.py`): Check if domains are registered using DNS and WHOIS queries

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/tonyliuzj/scan4domain.git
cd scan4domain
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Generate Domain List

Run the domain generator to create a list of domain combinations:

```bash
python3 generate.py
```

The script will prompt you for:
- **Length**: Number of characters in the domain label (e.g., 5 for LLLLL)
- **Template**: Pattern using `+` as wildcard (e.g., `a++++` or `a++++.com`)
- **TLD**: Top-level domain (e.g., com, net, org)

Example:
```
How many Ls (length of domain label)? e.g., 5 for LLLLL: 5
Template (use '+' as wildcard). Example: a++++ or a++++.com
Press Enter for default (+++++): a++++
Enter TLD (e.g., com, net, org): com
```

This will generate a file like `allll.com.txt` containing all possible combinations.

### Check Domain Registration

Run the domain checker to filter out registered domains:

```bash
python3 main.py
```

The script will:
1. Show available .txt files in the current directory
2. Prompt you to select a file to process
3. Ask for the number of worker threads (default: 20)
4. Check each domain using DNS (A, AAAA, NS records) and WHOIS queries
5. Keep only unregistered domains in the file

**Options:**
- `--workers N`: Set number of worker threads
- `--dry-run`: Test without modifying files
- `--remove-uncertain`: Remove domains with uncertain status
- `--dns-timeout`: DNS query timeout in seconds (default: 2.5)
- `--whois-timeout`: WHOIS query timeout in seconds (default: 8.0)

Example:
```bash
python3 main.py --workers 30 --remove-uncertain
```

## Notes

- Large domain lists (e.g., 5+ character combinations) can be very large (100+ MB)
- The checker creates `.bak` backup files before modifying
- Press Ctrl+C to safely interrupt the checker (progress is saved)
- Resume-safe: You can run the checker multiple times on the same file

## License

This project is open source and available for personal and educational use.
