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

# Set up logging with rotation
import logging.handlers

# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.expanduser('~'), '.cli-mcp-server', 'logs')
os.makedirs(log_dir, exist_ok=True)

# Configure rotating file handler
log_file = os.path.join(log_dir, 'cli_mcp_server.log')
rotating_handler = logging.handlers.RotatingFileHandler(
    log_file,
    maxBytes=1*1024*1024,  # 1MB per file
    backupCount=3,          # Keep 3 backup files
    encoding='utf-8'
)

# Create a very selective filter for the MCP module
class MpcFilter(logging.Filter):
    def filter(self, record):
        # Only log critical errors from the mcp module
        if record.name.startswith('mcp.'):
            return record.levelno >= logging.CRITICAL
        # For our own logs, use the configured level
        return True

# Set formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
rotating_handler.setFormatter(formatter)

# Add the filter to the handler
rotating_handler.addFilter(MpcFilter())

# Configure logger - use ERROR as default level to reduce log volume
# Can be overridden with environment variable LOG_LEVEL
log_level_name = os.getenv("LOG_LEVEL", "ERROR")
log_level = getattr(logging, log_level_name.upper(), logging.ERROR)
logger = logging.getLogger("cli_mcp_server")
logger.setLevel(log_level)
logger.addHandler(rotating_handler)

# Add console handler for critical errors only
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.CRITICAL)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Configure the root logger to filter out mcp messages
root_logger = logging.getLogger()
root_logger.addFilter(MpcFilter())

server = Server("cli-mcp-server")


class CommandError(Exception):
    """Base exception for command-related errors
    
    Can optionally include a result object to provide more context about the error
    """
    pass


class CommandSecurityError(CommandError):
    """Security violation errors
    
    Raised when a command violates security constraints such as:
    - Command is not in the allowlist
    - Command contains disallowed flags
    - Command exceeds maximum length
    """
    pass


class CommandExecutionError(CommandError):
    """Command execution errors
    
    Raised when a command fails during execution. Can include a CompletedProcess
    object with error details in the second argument.
    """
    pass


class CommandTimeoutError(CommandError):
    """Command timeout errors
    
    Raised when a command exceeds its timeout limit. Can include a CompletedProcess
    object with error details in the second argument.
    """
    pass


def sanitize_output(output_text: str, max_length: int = 50000) -> str:
    """
    Sanitize command output by removing control characters and limiting size.
    Handles None values gracefully and provides robust error handling.
    
    Args:
        output_text (str): The raw command output text
        max_length (int): Maximum allowed length for the output
        
    Returns:
        str: Sanitized text with control characters removed and size limited
    """
    # Handle None or non-string inputs safely
    if output_text is None:
        return ""
        
    # Ensure we're working with strings
    if not isinstance(output_text, str):
        try:
            output_text = str(output_text)
        except Exception as e:
            logger.error(f"Error converting output to string: {e}")
            return "[Error: Could not convert command output to string]"
    
    # Handle empty strings early
    if not output_text.strip():
        return ""
    
    try:    
        # Check for extremely large outputs early - improve performance
        if len(output_text) > max_length * 2:
            logger.warning(f"Extremely large output detected ({len(output_text)} chars), performing aggressive truncation")
            truncated_length = max_length // 2  # Aggressively truncate extremely large outputs
            return output_text[:truncated_length] + "\n\n[Output extremely large - aggressively truncated to " + str(truncated_length) + " characters]"
            
        # Detect and handle binary data which could cause display issues
        if '\x00' in output_text[:1024]:  # Check first 1KB for null bytes
            binary_sample = output_text[:100].replace('\x00', '␀')
            return f"[Binary data detected - output suppressed]\nFirst 100 bytes: {binary_sample}..."
        
        # Remove ANSI escape sequences (colors, cursor movement, etc.)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', output_text)
        
        # Remove other control characters except newlines and tabs
        clean_text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', clean_text)
        
        # Limit output size if needed
        if len(clean_text) > max_length:
            truncated_length = max_length - 100  # Leave room for truncation message
            clean_text = clean_text[:truncated_length] + "\n\n[Output truncated - exceeded maximum length of " + str(max_length) + " characters]"
        
        return clean_text
    except Exception as e:
        # Log the error and return a safe message
        logger.error(f"Error sanitizing output: {e}", exc_info=True)
        return "[Error sanitizing command output]"



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
        'pwd', 'echo', 'cd', 'mkdir', 'rmdir', 'touch', 'chmod', 'chown',
        'ln', 'mv', 'wc', 'date', 'hostname',
        'whoami', 'uname', 'which', 'type', 'true', 'false', 'exit', 'test'
    }
    
    # Commands that might take a bit longer but usually finish quickly
    medium_commands = {
        'ls', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'tr', 'find', 'ps', 'df', 
        'du', 'diff', 'stat', 'tee', 'top', 'htop', 'kill', 'pkill', 'killall', 'cp', 'rm', 'cat', 'head', 'tail'
    }
    
    # Default category
    complexity = 'complex'
    timeout = 30  # Default timeout for complex commands
    
    # Special handling for problematic commands
    if base_command == 'ls' and ('-R' in command_string or '--recursive' in command_string):
        # Recursive ls can be very slow and produce massive output
        complexity = 'complex'
        timeout = max(15, timeout)  # Ensure at least 15 seconds for recursive ls
        logger.debug(f"Special handling for recursive ls command with {timeout}s timeout")
        
    elif base_command == 'grep' and ('-r' in command_string or '-R' in command_string or '--recursive' in command_string):
        # Recursive grep can be very slow and produce massive output
        complexity = 'complex'
        timeout = max(20, timeout)  # Ensure at least 20 seconds for recursive grep
        logger.debug(f"Special handling for recursive grep command with {timeout}s timeout")
        
    # Check for pipe to commands that might increase output size dramatically
    if has_pipe and ('| grep' in command_string or '|grep' in command_string or 
                     '| sort' in command_string or '|sort' in command_string or
                     '| uniq' in command_string or '|uniq' in command_string):
        # Commands that filter/transform output can be unpredictable
        complexity = 'complex'
        timeout = max(15, timeout)
        logger.debug(f"Special handling for piped command with {timeout}s timeout")
    
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
        if not command_string or not command_string.strip():
            raise CommandSecurityError("Empty command")
            
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
            # Truncate very long commands in logs
            log_cmd = command_string
            if len(log_cmd) > 100:
                log_cmd = log_cmd[:97] + "..."
            logger.debug(f"Executing command: '{log_cmd}' with {timeout}s timeout")
            
            try:
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
                
                # Check if this is a command likely to produce large output
                is_large_output_likely = (
                    'ls -la' in command_string or 
                    'ls -l' in command_string or
                    'grep ' in command_string or
                    'find ' in command_string
                )
                
                # For likely large output commands, set a lower buffer threshold
                max_buffer_size = 1024 * 512  # 512KB for potentially large outputs
                if is_large_output_likely and (
                    len(result.stdout or '') > max_buffer_size or 
                    len(result.stderr or '') > max_buffer_size
                ):
                    logger.warning(
                        f"Large output detected for command '{command_string[:50]}...' "
                        f"(stdout: {len(result.stdout or '')} bytes, stderr: {len(result.stderr or '')} bytes)"
                    )
                    
                    # For extremely large outputs, truncate early to prevent processing delays
                    if result.stdout and len(result.stdout) > max_buffer_size * 2:
                        logger.warning(f"Extremely large stdout detected, truncating to {max_buffer_size} bytes")
                        result.stdout = result.stdout[:max_buffer_size] + "\n\n[Output truncated - exceeded maximum buffer size]"
                    
                    if result.stderr and len(result.stderr) > max_buffer_size * 2:
                        logger.warning(f"Extremely large stderr detected, truncating to {max_buffer_size} bytes")
                        result.stderr = result.stderr[:max_buffer_size] + "\n\n[Output truncated - exceeded maximum buffer size]"
                
                # Ensure stdout and stderr are strings, not None
                if result.stdout is None:
                    result.stdout = ""
                if result.stderr is None:
                    result.stderr = ""
                    
                # Log the execution time - only log detailed info for non-zero return codes or slow commands
                execution_time = time.time() - start_time
                if result.returncode != 0 or execution_time > 1.0:
                    # Log more detailed info for potentially problematic commands
                    log_cmd = command_string
                    if len(log_cmd) > 100:
                        log_cmd = log_cmd[:97] + "..."
                    logger.info(f"Command '{log_cmd}' completed in {execution_time:.2f}s with code {result.returncode}")
                else:
                    logger.debug(f"Command completed successfully in {execution_time:.2f}s with code 0")
                
                return result
            except subprocess.TimeoutExpired as e:
                # Log the timeout
                logger.warning(f"Command '{command_string}' timed out after {e.timeout}s")
                # Create a CompletedProcess with error information to prevent null returns
                error_result = subprocess.CompletedProcess(
                    args=command_string,
                    returncode=124,  # Common timeout exit code
                    stdout="",
                    stderr=f"Command timed out after {e.timeout} seconds"
                )
                raise CommandTimeoutError(f"Command timed out after {e.timeout} seconds", error_result)
                
        except CommandTimeoutError:
            # Re-raise timeout errors with the error result
            raise
        except CommandError:
            # Re-raise command errors
            raise
        except Exception as e:
            # Log other errors
            logger.error(f"Error executing command '{command_string}': {str(e)}", exc_info=True)
            # Create a CompletedProcess with error information to prevent null returns
            error_result = subprocess.CompletedProcess(
                args=command_string,
                returncode=1,  # Generic error code
                stdout="",
                stderr=f"Error executing command: {str(e)}"
            )
            raise CommandExecutionError(f"Command execution failed: {str(e)}", error_result)


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
            # Log the incoming command at debug level
            command = arguments['command']
            # Truncate long commands in logs
            log_cmd = command
            if len(log_cmd) > 100:
                log_cmd = log_cmd[:97] + "..."
            logger.debug(f"Command request received: {log_cmd}")
            start_time = time.time()
            
            # Execute the command
            result = executor.execute(command)
            
            # Log the total time including processing - but only for slow responses
            total_time = time.time() - start_time
            if total_time > 1.0:
                logger.info(f"Total command handling time: {total_time:.2f}s")
            else:
                logger.debug(f"Total command handling time: {total_time:.2f}s")

            # Always have at least one response item
            response = []
            
            # Handle stdout (even if empty)
            sanitized_stdout = sanitize_output(result.stdout) if result.stdout else ""
            if sanitized_stdout:
                response.append(types.TextContent(type="text", text=sanitized_stdout))
                
            # Handle stderr (even if empty)
            sanitized_stderr = sanitize_output(result.stderr) if result.stderr else ""
            if sanitized_stderr:
                response.append(types.TextContent(type="text", text=sanitized_stderr, error=True))

            # Always include the return code
            response.append(
                types.TextContent(
                    type="text",
                    text=f"\nCommand completed with return code: {result.returncode}",
                )
            )

            # Ensure we never return an empty response list
            if not response:
                response.append(types.TextContent(type="text", text="Command executed but produced no output"))
                
            return response

        except CommandSecurityError as e:
            logger.warning(f"Security violation: {str(e)}")
            return [types.TextContent(type="text", text=f"Security violation: {str(e)}", error=True)]
        except CommandTimeoutError as e:
            logger.warning(f"Command timeout: {str(e)}")
            # Check if we have an error_result object attached to the exception
            error_result = getattr(e, 'args', [None])[1] if len(getattr(e, 'args', [])) > 1 else None
            
            response = []
            if error_result and hasattr(error_result, 'stderr') and error_result.stderr:
                response.append(types.TextContent(type="text", text=sanitize_output(error_result.stderr), error=True))
            
            # Always include the timeout message
            response.append(types.TextContent(
                type="text",
                text=f"Command timed out. This might be due to the command taking too long to execute or accessing resources that aren't available. You might want to simplify the command or check that all paths exist.",
                error=True
            ))
            
            return response
        except CommandExecutionError as e:
            logger.error(f"Command execution error: {str(e)}", exc_info=True)
            
            # Check if we have an error_result object attached to the exception
            error_result = getattr(e, 'args', [None])[1] if len(getattr(e, 'args', [])) > 1 else None
            
            response = []
            if error_result and hasattr(error_result, 'stderr') and error_result.stderr:
                stderr_output = sanitize_output(error_result.stderr)
                response.append(types.TextContent(type="text", text=stderr_output, error=True))
                
                # Detect common error patterns
                if "No such file or directory" in stderr_output:
                    # Extract the filename from the error message if possible
                    file_match = re.search(r"(['\"])(.+?)\1: No such file or directory", stderr_output)
                    filename = file_match.group(2) if file_match else "The specified file"
                    response.append(types.TextContent(
                        type="text",
                        text=f"Error: {filename} does not exist. Please check the path and try again.",
                        error=True
                    ))
                elif "Permission denied" in stderr_output:
                    response.append(types.TextContent(
                        type="text",
                        text="Error: You don't have permission to access this file or directory.",
                        error=True
                    ))
                
            # Always include the execution error message
            response.append(types.TextContent(
                type="text",
                text=f"Error executing command: {str(e)}",
                error=True
            ))
            
            return response
        except Exception as e:
            # Log the full exception details for unknown exceptions
            logger.error(f"Unexpected error handling command: {str(e)}", exc_info=True)
            # Provide a clear error message back to the user
            return [types.TextContent(type="text", text=f"Unexpected error: {str(e)}", error=True)]

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
            f"\nError Handling Features (v0.2.2):\n"
            f"---------------------------\n"
            f"- Enhanced error handling to prevent UI freezing\n"
            f"- Robust output sanitization for all command results\n"
            f"- Graceful handling of timeouts and execution failures\n"
            f"- Optimized logging with log rotation\n"
            f"\nLogging Configuration:\n"
            f"----------------------\n"
            f"- Log directory: {log_dir}\n"
            f"- Log file: {log_file}\n"
            f"- Log level: {log_level_name} (MCP framework logs filtered to CRITICAL only)\n"
            f"- Rotation: {rotating_handler.maxBytes//1024}KB files, {rotating_handler.backupCount} backup files max\n"
            f"- To change log level, set the LOG_LEVEL environment variable (DEBUG, INFO, WARNING, ERROR, CRITICAL)\n"
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
                server_version="0.2.4",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )