#!/usr/bin/env python3
"""
Test script for CLI MCP Server error handling
This script simulates various error conditions to verify our fixes
"""

import os
import sys
import asyncio
from src.cli_mcp_server.server import executor, handle_call_tool, sanitize_output
import mcp.types as types

async def test_error_handling():
    """Test various error scenarios to validate our fixes"""
    print("Testing CLI MCP Server Error Handling")
    print("=====================================")
    
    # Test 1: Empty command
    print("\nTest 1: Empty command")
    result = await handle_call_tool("run_command", {"command": ""})
    print_result(result)
    
    # Test 2: Invalid command
    print("\nTest 2: Invalid command")
    result = await handle_call_tool("run_command", {"command": "nonexistentcommand123"})
    print_result(result)
    
    # Test 3: Command that would time out (simulate by setting a very low timeout)
    print("\nTest 3: Timeout simulation")
    old_timeout = executor.security_config.command_timeout
    executor.security_config.command_timeout = 1
    result = await handle_call_tool("run_command", {"command": "sleep 3"})
    executor.security_config.command_timeout = old_timeout
    print_result(result)
    
    # Test 4: Security violation
    print("\nTest 4: Security violation test")
    old_allow_all = executor.security_config.allow_all_commands
    executor.security_config.allow_all_commands = False
    executor.security_config.allowed_commands = {"ls", "cat", "pwd"}
    if "nonexistentcommand123" not in executor.security_config.allowed_commands:
        result = await handle_call_tool("run_command", {"command": "nonexistentcommand123"})
        print_result(result)
    executor.security_config.allow_all_commands = old_allow_all
    
    # Test 5: Command with null output
    print("\nTest 5: Command with null output")
    result = await handle_call_tool("run_command", {"command": ":"})  # Null command in bash
    print_result(result)
    
    # Test 6: Output sanitization
    print("\nTest 6: Output sanitization")
    ansi_text = "\033[31mThis is red\033[0m and this is \033[1mbold\033[0m"
    sanitized = sanitize_output(ansi_text)
    print(f"Original: {ansi_text}")
    print(f"Sanitized: {sanitized}")
    
    # Test 7: None value sanitization
    print("\nTest 7: None value sanitization")
    sanitized = sanitize_output(None)
    print(f"Sanitized None: '{sanitized}'")
    
    print("\nAll tests completed!")

def print_result(result):
    """Print the result in a readable format"""
    if not result:
        print("  ERROR: Empty result!")
        return
        
    for i, item in enumerate(result):
        error_status = " (ERROR)" if getattr(item, "error", False) else ""
        print(f"  Response {i+1}{error_status}: {item.text[:100]}{'...' if len(item.text) > 100 else ''}")

if __name__ == "__main__":
    # Set environment variables for testing
    os.environ["ALLOWED_DIR"] = "/home/ty/Repositories"
    os.environ["ALLOWED_COMMANDS"] = "all"
    os.environ["ALLOWED_FLAGS"] = "all"
    
    asyncio.run(test_error_handling())
