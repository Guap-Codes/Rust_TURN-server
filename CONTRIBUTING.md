# Contributing to turn-server-rs

First off, thank you for considering contributing to turn-server-rs! It's people like you that make this TURN server implementation better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include logs if relevant

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* Use a clear and descriptive title
* Provide a step-by-step description of the suggested enhancement
* Provide specific examples to demonstrate the steps
* Describe the current behavior and explain which behavior you expected to see instead
* Explain why this enhancement would be useful

### Pull Requests

* Fork the repo and create your branch from `main`
* If you've added code that should be tested, add tests
* If you've changed APIs, update the documentation
* Ensure the test suite passes
* Make sure your code lints
* Issue that pull request!

## Development Process

1. Fork the repository
2. Create a new branch: `git checkout -b my-branch-name`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin my-branch-name`
5. Submit a pull request

### Rust Style Guide

* Use `rustfmt` to format your code
* Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
* Write documentation for public APIs
* Add tests for new functionality

### Testing

* Write unit tests for new code
* Ensure all tests pass: `cargo test`
* Add integration tests for new features
* Test both UDP and TCP functionality
* Verify rate limiting and authentication

## Project Structure

```
src/
├── auth/       # Authentication handling
├── config/     # Configuration management
├── error.rs     # Error types and handling
├── rate_limit.rs # Rate limiting functionality
├── transport/  # UDP/TCP transport layer
├── turn/       # TURN protocol implementation
└── types.rs      # Common type definitions
```

## Documentation

* Document all public APIs
* Include examples in documentation
* Update README.md if needed
* Add comments for complex logic

## Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

* Open an issue
* Email the maintainers

Thank you for contributing! 