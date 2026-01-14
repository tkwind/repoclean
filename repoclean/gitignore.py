DEFAULT_GITIGNORE = """# Python
__pycache__/
*.py[cod]
*.pyd

# Virtual environments
.venv/
venv/

# Env files
.env

# Build outputs
dist/
build/
*.egg-info/

# Node (if applicable)
node_modules/

# IDEs
.vscode/
.idea/
"""

def get_default_gitignore() -> str:
    return DEFAULT_GITIGNORE
