# Developer Notes for CLI MCP Server

This document provides important information for developers working with the CLI MCP Server codebase, particularly focused on the error handling mechanisms added in version 0.2.2.

## Error Handling Architecture

The CLI MCP Server implements a multi-layered error handling approach to ensure that the UI never freezes due to unexpected responses or errors. This is particularly important when integrating with Claude and other LLM interfaces.

### Key Components

1. **Exception Classes**
   - `CommandError`: Base exception class
   - `CommandSecurityError`: For security violations
   - `CommandExecutionError`: For execution failures
   - `CommandTimeoutError`: For command timeouts

2. **Error Result Objects**
   - Commands that fail can attach a `CompletedProcess` object to exceptions
   - This ensures that even in error cases, we have a structured object with stdout/stderr

3. **Sanitization Layer**
   - `sanitize_output()` function handles cleaning output from control characters
   - Robust handling of None, non-string values, and oversized outputs
   - Prevents UI disruption from unusual characters or excessive output

4. **Response Construction**
   - Always returns a non-empty list of `TextContent` objects
   - Gracefully handles empty or null responses
   - Every error path has a dedicated response formatter

### Error Flow

When a command encounters an error:

1. The specific exception is raised with error details
2. Where possible, a structured error result is attached to provide context
3. The exception handler in `handle_call_tool()` formats an appropriate response
4. The sanitization layer cleans any output text
5. A non-empty response list is guaranteed to be returned

## New Features in v0.2.2

### Enhanced Error Handling

- Added better handling of None and invalid responses
- Improved sanitization for all output types
- Restructured exception flow to include error context

### Command Execution Improvements

- Better timeouts with adaptive behaviors
- Safer error result handling
- Improved status reporting for all command states

### Logging Enhancements

- Added comprehensive logging with `exc_info`
- Better structured logs for debugging
- Performance metrics for command execution

## Development Guidelines

When extending or modifying the code:

1. **Always Handle Errors Gracefully**
   - Never allow null responses to propagate
   - Use structured error objects where possible
   - Sanitize all output before returning

2. **Ensure Robust Responses**
   - Verify that responses are never empty
   - Include clear error messages for all failure modes
   - Provide fallback responses for unexpected situations

3. **Test Edge Cases**
   - Use the test_server.py script to verify error handling
   - Test with commands that might return unusual output
   - Verify timeout handling still works correctly

4. **Maintain Backward Compatibility**
   - Preserve the existing API where possible
   - Ensure security features remain intact
   - Maintain compatibility with Claude and other MCP clients

## Common Pitfalls

- **Error Handling**: Don't rely on standard exception messages; format them clearly
- **Response Lists**: Always ensure non-empty response lists are returned
- **Sanitization**: Remember to sanitize all command output before returning
- **Timeouts**: Use adaptive timeouts based on command complexity

By following these guidelines, the CLI MCP Server will continue to be a robust and reliable tool for secure command execution in LLM environments.
