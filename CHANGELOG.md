# Changelog

## v0.2.5 - 2025-03-19

### Fixed
- Addressed stability issues with `ls` and `grep` commands that could cause freezes
- Improved detection and handling of extremely large command outputs
- Enhanced error handling for failed commands, especially for non-existent files
- Fixed binary data handling to prevent display issues

### Added
- Special handling for recursive `ls` and `grep` commands with adjusted timeouts
- User-friendly error messages for common issues like "No such file or directory"
- Progressive output buffering for large responses
- Improved classification of commands that use pipes and filters

### Changed
- Moved `ls` and several file operation commands from simple to medium complexity category
- Enhanced output sanitization for better performance with large outputs
- Added aggressive truncation for extremely large outputs
- Improved detection and handling of binary data

## v0.2.4 - 2025-03-17

### Fixed
- Dramatically reduced logging by filtering MCP framework logs
- Fixed excessive log growth issue with custom filter

### Changed
- Reduced log file size to 1MB and backup count to 3
- Default log level changed to ERROR to minimize log volume
- Added custom MpcFilter to block non-critical MCP framework logs
- Updated security information display with new log filter details

## v0.2.3 - 2025-03-17

### Fixed
- Implemented log rotation to prevent excessive log file growth

### Added
- Optimized logging system with rotation and configurable log levels
- Log directory at ~/.cli-mcp-server/logs with 2MB file size limit
- LOG_LEVEL environment variable for configuring verbosity

### Changed
- Optimized logging to reduce verbosity for common operations
- Truncated long command strings in log messages
- Default log level changed to WARNING to reduce log volume
- Updated security information display to include logging configuration

## v0.2.2 - 2025-03-17

### Fixed
- Fixed issue where the server would freeze when receiving error responses
- Enhanced error handling to ensure valid responses in all cases
- Improved sanitization of command output to handle edge cases
- Implemented log rotation to prevent excessive log file growth

### Added
- Extended error objects that include detailed error information
- Failsafe response construction for all command paths
- Optimized logging system with rotation and configurable log levels
- Log directory at ~/.cli-mcp-server/logs with 2MB file size limit
- LOG_LEVEL environment variable for configuring verbosity
- Test script for validating error handling
- Developer documentation for extending the server

### Changed
- Enhanced exception handling in the handle_call_tool function
- Improved command execution with better error reporting
- Optimized logging to reduce verbosity for common operations
- Truncated long command strings in log messages
- Updated security information display to include logging configuration
- Default log level changed to WARNING to reduce log volume

## v0.2.1 - 2024-03-10

### Added
- Output sanitization function to remove control characters and ANSI codes
- Adaptive timeouts based on command complexity
- Command classification system for determining appropriate timeouts

### Changed
- Modified command response handling to improve stability
- Enhanced error messages for timeouts and failures
- Added comprehensive logging system

## v0.2.0 - 2024-03-09

### Added
- Initial release with shell operator support
- Support for command execution with shell=True
- Preserved security features from the original implementation

### Changed
- Modified command validation to allow shell operators
- Enhanced security documentation
- Added detailed docstrings
