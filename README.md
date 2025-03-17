# CLI MCP Server
# Modified by angrysky56 to allow shell and operators to facilitate Claude's coding abilities.

Summary of the changes:

Added Output Sanitization Function:

Created a new sanitize_output() function that:

Removes ANSI escape sequences (colors, cursor movements, etc.)
Filters out control characters that could disrupt the interface
Limits the output size to prevent buffer overflows
Adds a clear message when output is truncated




Modified Command Response Handling:

Updated the handle_call_tool() function to sanitize stdout and stderr before sending to Claude Desktop
Applied sanitization to both standard output and error streams


Preserved Shell Operator Functionality:

Kept the shell=True flag to maintain support for &&, |, and other shell operators
Ensured all command chaining capabilities remain intact


Added Proper Documentation:

Included detailed docstrings for the new function
Explained the purpose of the sanitization

Changes Made to Fix the Freezing Issue

Adaptive Timeouts Based on Command Complexity:

Simple commands (like ls, chmod, pwd) now use a 3-second timeout
Medium complexity commands use a 10-second timeout
Complex commands use the original default timeout (30 seconds)


Command Classification System:

Added a classify_command_complexity function that intelligently categorizes commands
Detects shell operators like pipes, redirections, and chains to determine complexity


Improved Error Handling:

Enhanced timeout error messages with more helpful suggestions
Better logging of command execution times and errors


Logging System:

Added comprehensive logging to track command execution times
Logs command classification, execution time, and any errors
Helps diagnose problems without interfering with the interface


Performance Optimizations:

Quick commands now respond nearly instantly
Added timing tracking to identify slow operations



These changes should prevent Claude Desktop from freezing on simple commands while still allowing complex operations to work properly with shell operators like && and |.

## Improved Error Handling and Resilience in v0.2.2

The latest update (v0.2.2) fixes the issue where the server would freeze when handling error responses. This version includes a complete overhaul of the error handling system to ensure that Claude always receives a valid, properly formatted response regardless of what happens during command execution.

Key improvements:

- **Never Freezes on Errors**: The server now handles all error conditions gracefully, never returning null responses that could cause the interface to freeze
- **Extended Exception System**: Added error result objects to exceptions that provide structured error data
- **Failsafe Response Construction**: Every response path now has multiple layers of validation to ensure at least one valid text item is returned
- **Improved Sanitization**: Enhanced output sanitization to handle a wider variety of edge cases
- **Robust Command Execution**: Better handling of command timeouts and execution failures

These changes make the CLI MCP Server significantly more reliable, preventing freezing even when commands fail in unusual ways.
---

A secure Model Context Protocol (MCP) server implementation for executing controlled command-line operations with
comprehensive security features.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![MCP Protocol](https://img.shields.io/badge/MCP-Compatible-green)
[![smithery badge](https://smithery.ai/badge/cli-mcp-server)](https://smithery.ai/protocol/cli-mcp-server)

<a href="https://glama.ai/mcp/servers/q89277vzl1"><img width="380" height="200" src="https://glama.ai/mcp/servers/q89277vzl1/badge" /></a>

---

# Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Configuration](#configuration)
4. [Available Tools](#available-tools)
    - [run_command](#run_command)
    - [show_security_rules](#show_security_rules)
5. [Usage with Claude Desktop](#usage-with-claude-desktop)
    - [Development/Unpublished Servers Configuration](#developmentunpublished-servers-configuration)
    - [Published Servers Configuration](#published-servers-configuration)
6. [Security Features](#security-features)
7. [Error Handling](#error-handling)
8. [Development](#development)
    - [Prerequisites](#prerequisites)
    - [Building and Publishing](#building-and-publishing)
    - [Debugging](#debugging)
9. [License](#license)

---

## Overview

This MCP server enables secure command-line execution with robust security measures including command whitelisting, path
validation, and execution controls. Perfect for providing controlled CLI access to LLM applications while maintaining security.

## Features

- 🔒 Secure command execution with strict validation
- ⚙️ Configurable command and flag whitelisting with 'all' option
- 🛡️ Path traversal prevention and validation
- 🚫 Shell operator injection protection
- ⏱️ Execution timeouts and length limits
- 📝 Detailed error reporting
- 🔄 Async operation support
- 🎯 Working directory restriction and validation

## Configuration

Configure the server using environment variables:

| Variable             | Description                                          | Default            |
|---------------------|------------------------------------------------------|-------------------|
| `ALLOWED_DIR`       | Base directory for command execution (Required)      | None (Required)   |
| `ALLOWED_COMMANDS`  | Comma-separated list of allowed commands or 'all'    | `ls,cat,pwd`      |
| `ALLOWED_FLAGS`     | Comma-separated list of allowed flags or 'all'       | `-l,-a,--help`    |
| `MAX_COMMAND_LENGTH`| Maximum command string length                        | `1024`            |
| `COMMAND_TIMEOUT`   | Command execution timeout (seconds)                  | `30`              |

Note: Setting `ALLOWED_COMMANDS` or `ALLOWED_FLAGS` to 'all' will allow any command or flag respectively.

## Installation

To install CLI MCP Server for Claude Desktop automatically via [Smithery](https://smithery.ai/protocol/cli-mcp-server):

```bash
npx @smithery/cli install cli-mcp-server --client claude
```

## Available Tools

### run_command

Executes whitelisted CLI commands within allowed directories.

**Input Schema:**
```json
{
  "command": {
    "type": "string",
    "description": "Single command to execute (e.g., 'ls -l' or 'cat file.txt')"
  }
}
```

**Security Notes:**
- Shell operators (&&, |, >, >>) are not supported
- Commands must be whitelisted unless ALLOWED_COMMANDS='all'
- Flags must be whitelisted unless ALLOWED_FLAGS='all'
- All paths are validated to be within ALLOWED_DIR

### show_security_rules

Displays current security configuration and restrictions, including:
- Working directory
- Allowed commands
- Allowed flags
- Security limits (max command length and timeout)

## Usage with Claude Desktop

Add to your `~/Library/Application\ Support/Claude/claude_desktop_config.json`:

> Development/Unpublished Servers Configuration

```json
{
  "mcpServers": {
    "cli-mcp-server": {
      "command": "uv",
      "args": [
        "--directory",
        "<path/to/the/repo>/cli-mcp-server",
        "run",
        "cli-mcp-server"
      ],
      "env": {
        "ALLOWED_DIR": "</your/desired/dir>",
        "ALLOWED_COMMANDS": "ls,cat,pwd,echo",
        "ALLOWED_FLAGS": "-l,-a,--help,--version",
        "MAX_COMMAND_LENGTH": "1024",
        "COMMAND_TIMEOUT": "30"
      }
    }
  }
}
```

> Published Servers Configuration

```json
{
  "mcpServers": {
    "cli-mcp-server": {
      "command": "uvx",
      "args": [
        "cli-mcp-server"
      ],
      "env": {
        "ALLOWED_DIR": "</your/desired/dir>",
        "ALLOWED_COMMANDS": "ls,cat,pwd,echo",
        "ALLOWED_FLAGS": "-l,-a,--help,--version",
        "MAX_COMMAND_LENGTH": "1024",
        "COMMAND_TIMEOUT": "30"
      }
    }
  }
}
```
> In case it's not working or showing in the UI, clear your cache via `uv clean`.

## Security Features

- ✅ Command whitelist enforcement with 'all' option
- ✅ Flag validation with 'all' option
- ✅ Path traversal prevention and normalization
- ✅ Shell operator blocking
- ✅ Command length limits
- ✅ Execution timeouts
- ✅ Working directory restrictions
- ✅ Symlink resolution and validation

## Error Handling

The server provides detailed error messages for:

- Security violations (CommandSecurityError)
- Command timeouts (CommandTimeoutError)
- Invalid command formats
- Path security violations
- Execution failures (CommandExecutionError)
- General command errors (CommandError)

## Development

### Prerequisites

- Python 3.10+
- MCP protocol library

### Building and Publishing

To prepare the package for distribution:

1. Sync dependencies and update lockfile:
    ```bash
    uv sync
    ```

2. Build package distributions:
    ```bash
    uv build
    ```

   > This will create source and wheel distributions in the `dist/` directory.

3. Publish to PyPI:
   ```bash
   uv publish --token {{YOUR_PYPI_API_TOKEN}}
   ```

### Debugging

Since MCP servers run over stdio, debugging can be challenging. For the best debugging
experience, we strongly recommend using the [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

You can launch the MCP Inspector via [`npm`](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) with
this command:

```bash
npx @modelcontextprotocol/inspector uv --directory {{your source code local directory}}/cli-mcp-server run cli-mcp-server
```

Upon launching, the Inspector will display a URL that you can access in your browser to begin debugging.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

For more information or support, please open an issue on the project repository.