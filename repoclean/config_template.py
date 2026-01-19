DEFAULT_REPOCLEAN_TOML = """[repoclean]
# Large file threshold in MB
max_file_mb = 25

# Skip files larger than this during secrets scan (KB)
max_secret_file_kb = 256

# Ignore paths (relative to repo root)
ignore_dirs = ["node_modules", "dist", "build"]
ignore_files = []
ignore_extensions = [".bin"]

# Allow secrets in these folders (relative paths)
allow_secrets_in = ["tests/", "examples/"]

# --- Optional: Customize junk detection rules ---
# These EXTEND repoclean defaults (they do not replace them)

junk_dirs = []
junk_files = []
junk_extensions = []
"""
