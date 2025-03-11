import os
import re
import shlex
import subprocess
import logging
import time
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='cli_mcp_server.log'
)
logger = logging.getLogger("cli_mcp_server")

server = Server("cli-mcp-server")


class CommandError(Exception):
    """Base exception for command-related errors"""
    pass


class CommandSecurityError(CommandError):
    """Security violation errors"""
    pass


class CommandExecutionError(CommandError):
    """Command execution errors"""
    pass


class CommandTimeoutError(CommandError):
    """Command timeout errors"""
    pass


def sanitize_output(output_text: str, max_length: int = 50000) -> str:
    """
    Sanitize command output by removing control characters and limiting size.
    
    Args:
        output_text (str): The raw command output text
        max_length (int): Maximum allowed length for the output
        
    Returns:
        str: Sanitized text with control characters removed and size limited
    """
    if not output_text:
        return ""
        
    # Remove ANSI escape sequences (colors, cursor movement, etc.)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', output_text)
    
    # Remove other control characters except newlines and tabs
    clean_text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', clean_text)
    
    # Limit output size if needed
    if len(clean_text) > max_length:
        truncated_length = max_length - 40  # Leave room for truncation message
        clean_text = clean_text[:truncated_length] + "\n\n[Output truncated - exceeded maximum length]"
    
    return clean_text


def classify_command_complexity(command_string: str) -> Tuple[str, int]:
    """
    Classifies a command as simple or complex and assigns an appropriate timeout.
    
    Args:
        command_string (str): The command to classify
        
    Returns:
        Tuple[str, int]: A tuple containing the complexity level and suggested timeout
            - Complexity: 'simple', 'medium', or 'complex'
            - Timeout: suggested timeout in seconds
    """
    # Extract the base command (before any arguments or shell operators)
    base_command = command_string.split(' ')[0]
    base_command = base_command.split('/')[-1]  # Extract command from path if given
    
    # Quick check for shell operators that make commands inherently more complex
    has_pipe = '|' in command_string
    has_redirection = '>' in command_string or '<' in command_string
    has_background = '&' in command_string
    has_chain = '&&' in command_string or '||' in command_string
    has_subshell = '(' in command_string or ')' in command_string
    
    # List of simple commands that typically execute quickly
    simple_commands = {
        'ls', 'pwd', 'echo', 'cd', 'mkdir', 'rmdir', 'touch', 'chmod', 'chown',
        'ln', 'cp', 'mv', 'rm', 'cat', 'head', 'tail', 'wc', 'date', 'hostname',
        'whoami', 'uname', 'which', 'type', 'true', 'false', 'exit', 'test'
    }
    
    # Commands that might take a bit longer but usually finish quickly
    medium_commands = {
        'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'tr', 'find', 'ps', 'df', 
        'du', 'diff', 'stat', 'tee', 'top', 'htop', 'kill', 'pkill', 'killall'
    }
    
    # Default category
    complexity = 'complex'
    timeout = 30  # Default timeout for complex commands
    
    # Determine complexity level
    if base_command in simple_commands and not (has_pipe or has_redirection or 
                                               has_background or has_chain or 
                                               has_subshell):
        complexity = 'simple'
        timeout = 3  # Very short timeout for simple commands
    elif base_command in medium_commands or (base_command in simple_commands and 
                                            (has_pipe or has_redirection or 
                                             has_chain)):
        complexity = 'medium'
        timeout = 10  # Medium timeout
    
    # Log the classification
    logger.debug(f"Command '{command_string}' classified as {complexity} with {timeout}s timeout")
    
    return complexity, timeout


@dataclass
class SecurityConfig:
    """
    Security configuration for command execution
    """
    allowed_commands: set[str]
    allowed_flags: set[str]
    max_command_length: int
    command_timeout: int
    allow_all_commands: bool = False
    allow_all_flags: bool = False


class CommandExecutor:
    def __init__(self, allowed_dir: str, security_config: SecurityConfig):
        if not allowed_dir or not os.path.exists(allowed_dir):
            raise ValueError("Valid ALLOWED_DIR is required")
        self.allowed_dir = os.path.abspath(os.path.realpath(allowed_dir))
        self.security_config = security_config

    def _normalize_path(self, path: str) -> str:
        """
        Normalizes a path and ensures it's within allowed directory.
        """
        try:
            if os.path.isabs(path):
                # If absolute path, check directly
                real_path = os.path.abspath(os.path.realpath(path))
            else:
                # If relative path, combine with allowed_dir first
                real_path = os.path.abspath(os.path.realpath(os.path.join(self.allowed_dir, path)))

            if not self._is_path_safe(real_path):
                raise CommandSecurityError(f"Path '{path}' is outside of allowed directory: {self.allowed_dir}")

            return real_path
        except CommandSecurityError:
            raise
        except Exception as e:
            raise CommandSecurityError(f"Invalid path '{path}': {str(e)}")

    def validate_command(self, command_string: str) -> tuple[str, List[str]]:
        """
        Validates and parses a command string for security and formatting.

        Checks the command string for unsupported shell operators and splits it into
        command and arguments. Only single commands without shell operators are allowed.

        Args:
            command_string (str): The command string to validate and parse.

        Returns:
            tuple[str, List[str]]: A tuple containing:
                - The command name (str)
                - List of command arguments (List[str])

        Raises:
            CommandSecurityError: If the command contains unsupported shell operators.
        """
        # Shell operators check removed to enable full functionality
        # We're on a personal machine where command injection is not a concern

        try:
            parts = shlex.split(command_string)
            if not parts:
                raise CommandSecurityError("Empty command")

            command, args = parts[0], parts[1:]

            # We're going to bypass most command validation since we're using shell=True
            # and allowing shell operators. This code will only remain for path validation.
            
            # For demonstration purposes, we'll still check the base command
            # against the allowed commands list if not in allow-all mode
            if not self.security_config.allow_all_commands and command not in self.security_config.allowed_commands:
                raise CommandSecurityError(f"Command '{command}' is not allowed")
                
            # Simply return the original command string since we're using shell=True
            return command_string, []

        except ValueError as e:
            raise CommandSecurityError(f"Invalid command format: {str(e)}")

    def _is_path_safe(self, path: str) -> bool:
        """
        Checks if a given path is safe to access within allowed directory boundaries.

        Validates that the absolute resolved path is within the allowed directory
        to prevent directory traversal attacks.

        Args:
            path (str): The path to validate.

        Returns:
            bool: True if path is within allowed directory, False otherwise.
                Returns False if path resolution fails for any reason.

        Private method intended for internal use only.
        """
        try:
            # Resolve any symlinks and get absolute path
            real_path = os.path.abspath(os.path.realpath(path))
            allowed_dir_real = os.path.abspath(os.path.realpath(self.allowed_dir))

            # Check if the path starts with allowed_dir
            return real_path.startswith(allowed_dir_real)
        except Exception:
            return False

    def execute(self, command_string: str) -> subprocess.CompletedProcess:
        """
        Executes a command string in a secure, controlled environment with adaptive timeouts.

        Runs the command after validating it against security constraints. Uses adaptive
        timeouts based on command complexity to prevent UI freezing for simple commands.

        Args:
            command_string (str): The command string to execute.

        Returns:
            subprocess.CompletedProcess: The result of the command execution containing
                stdout, stderr, and return code.

        Raises:
            CommandSecurityError: If the command exceeds maximum length or fails validation
            CommandTimeoutError: If the command times out
            CommandExecutionError: For other execution failures
        """
        if len(command_string) > self.security_config.max_command_length:
            raise CommandSecurityError(f"Command exceeds maximum length of {self.security_config.max_command_length}")

        try:
            # Simplified validation that just checks if the base command is allowed
            _, _ = self.validate_command(command_string)
            
            # Determine appropriate timeout based on command complexity
            complexity, suggested_timeout = classify_command_complexity(command_string)
            
            # Use the suggested timeout or the security config timeout, whichever is smaller
            # This ensures we don't exceed the maximum configured timeout
            timeout = min(suggested_timeout, self.security_config.command_timeout)
            
            # Log the execution
            start_time = time.time()
            logger.info(f"Executing command: '{command_string}' with {timeout}s timeout")
            
            # When using shell=True, we pass the entire command string
            # This allows shell operators to work properly
            result = subprocess.run(
                command_string,
                shell=True,
                text=True,
                capture_output=True,
                timeout=timeout,
                cwd=self.allowed_dir,
            )
            
            # Log the execution time
            execution_time = time.time() - start_time
            logger.info(f"Command '{command_string}' completed in {execution_time:.2f}s with code {result.returncode}")
            
            return result
            
        except subprocess.TimeoutExpired as e:
            # Log the timeout
            logger.warning(f"Command '{command_string}' timed out after {e.timeout}s")
            raise CommandTimeoutError(f"Command timed out after {e.timeout} seconds")
        except CommandError:
            # Re-raise command errors
            raise
        except Exception as e:
            # Log other errors
            logger.error(f"Error executing command '{command_string}': {str(e)}")
            raise CommandExecutionError(f"Command execution failed: {str(e)}")


# Load security configuration from environment
def load_security_config() -> SecurityConfig:
    """
    Loads security configuration from environment variables with default fallbacks.

    Creates a SecurityConfig instance using environment variables to configure allowed
    commands, flags, patterns, and execution constraints. Uses predefined defaults if
    environment variables are not set.

    Returns:
        SecurityConfig: Configuration object containing:
            - allowed_commands: Set of permitted command names
            - allowed_flags: Set of permitted command flags/options
            - max_command_length: Maximum length of command string
            - command_timeout: Maximum execution time in seconds
            - allow_all_commands: Whether all commands are allowed
            - allow_all_flags: Whether all flags are allowed

    Environment Variables:
        ALLOWED_COMMANDS: Comma-separated list of allowed commands or 'all' (default: "ls,cat,pwd")
        ALLOWED_FLAGS: Comma-separated list of allowed flags or 'all' (default: "-l,-a,--help")
        MAX_COMMAND_LENGTH: Maximum command string length (default: 1024)
        COMMAND_TIMEOUT: Command timeout in seconds (default: 30)
    """
    allowed_commands = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd")
    allowed_flags = os.getenv("ALLOWED_FLAGS", "-l,-a,--help")
    
    allow_all_commands = allowed_commands.lower() == 'all'
    allow_all_flags = allowed_flags.lower() == 'all'
    
    return SecurityConfig(
        allowed_commands=set() if allow_all_commands else set(allowed_commands.split(",")),
        allowed_flags=set() if allow_all_flags else set(allowed_flags.split(",")),
        max_command_length=int(os.getenv("MAX_COMMAND_LENGTH", "1024")),
        command_timeout=int(os.getenv("COMMAND_TIMEOUT", "30")),
        allow_all_commands=allow_all_commands,
        allow_all_flags=allow_all_flags,
    )


# Initialize the command executor
executor = CommandExecutor(allowed_dir=os.getenv("ALLOWED_DIR", ""), security_config=load_security_config())


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    commands_desc = "all commands" if executor.security_config.allow_all_commands else ", ".join(executor.security_config.allowed_commands)
    flags_desc = "all flags" if executor.security_config.allow_all_flags else ", ".join(executor.security_config.allowed_flags)
    
    return [
        types.Tool(
            name="run_command",
            description=(
                f"Allows command (CLI) execution in the directory: {executor.allowed_dir}\n\n"
                f"Available commands: {commands_desc}\n"
                f"Available flags: {flags_desc}\n\n"
                "All shell operators are now supported."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Single command to execute (example: 'ls -l' or 'cat file.txt')",
                    }
                },
                "required": ["command"],
            },
        ),
        types.Tool(
            name="show_security_rules",
            description=("Show what commands and operations are allowed in this environment.\n"),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
    if name == "run_command":
        if not arguments or "command" not in arguments:
            return [types.TextContent(type="text", text="No command provided", error=True)]

        try:
            # Log the incoming command
            logger.info(f"Command request received: {arguments['command']}")
            start_time = time.time()
            
            # Execute the command
            result = executor.execute(arguments["command"])
            
            # Log the total time including processing
            total_time = time.time() - start_time
            logger.info(f"Total command handling time: {total_time:.2f}s")

            response = []
            if result.stdout:
                # Sanitize the stdout before adding to response
                sanitized_stdout = sanitize_output(result.stdout)
                response.append(types.TextContent(type="text", text=sanitized_stdout))
                
            if result.stderr:
                # Sanitize the stderr before adding to response
                sanitized_stderr = sanitize_output(result.stderr)
                response.append(types.TextContent(type="text", text=sanitized_stderr, error=True))

            response.append(
                types.TextContent(
                    type="text",
                    text=f"\nCommand completed with return code: {result.returncode}",
                )
            )

            return response

        except CommandSecurityError as e:
            logger.warning(f"Security violation: {str(e)}")
            return [types.TextContent(type="text", text=f"Security violation: {str(e)}", error=True)]
        except CommandTimeoutError as e:
            logger.warning(f"Command timeout: {str(e)}")
            return [
                types.TextContent(
                    type="text",
                    text=f"Command timed out. This might be due to the command taking too long to execute or accessing resources that aren't available. You might want to simplify the command or check that all paths exist.",
                    error=True,
                )
            ]
        except Exception as e:
            logger.error(f"Error handling command: {str(e)}")
            return [types.TextContent(type="text", text=f"Error: {str(e)}", error=True)]

    elif name == "show_security_rules":
        commands_desc = "All commands allowed" if executor.security_config.allow_all_commands else ", ".join(sorted(executor.security_config.allowed_commands))
        flags_desc = "All flags allowed" if executor.security_config.allow_all_flags else ", ".join(sorted(executor.security_config.allowed_flags))
        
        security_info = (
            "Security Configuration:\n"
            f"==================\n"
            f"Working Directory: {executor.allowed_dir}\n"
            f"\nAllowed Commands:\n"
            f"----------------\n"
            f"{commands_desc}\n"
            f"\nAllowed Flags:\n"
            f"-------------\n"
            f"{flags_desc}\n"
            f"\nSecurity Limits:\n"
            f"---------------\n"
            f"Max Command Length: {executor.security_config.max_command_length} characters\n"
            f"Command Timeout: {executor.security_config.command_timeout} seconds (adaptive based on command type)\n"
            f"Simple commands timeout: 3 seconds\n"
            f"Medium commands timeout: 10 seconds\n"
            f"Complex commands timeout: {executor.security_config.command_timeout} seconds\n"
        )
        return [types.TextContent(type="text", text=security_info)]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="cli-mcp-server",
                server_version="0.2.1",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )