# Contributing to Linden's Script

First off, thank you for considering contributing to Linden's Script! It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by our commitment to providing a welcoming and inclusive environment. Please be respectful and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (JSON input, schema used, expected vs actual output)
- **Include your PowerShell version** (`$PSVersionTable`)
- **Include error messages** (full error output)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the suggested enhancement**
- **Explain why this enhancement would be useful**
- **List any alternatives you've considered**

### Pull Requests

1. **Fork the repo** and create your branch from `main`
2. **Write tests** for any new functionality
3. **Ensure the test suite passes** (`Invoke-Pester ./tests`)
4. **Follow the existing code style**
5. **Write clear commit messages**
6. **Update documentation** as needed

## Development Setup

```powershell
# Clone your fork
git clone https://github.com/YOUR_USERNAME/lindens-script.git
cd lindens-script

# Install Pester for testing
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run tests
Invoke-Pester ./tests -Output Detailed
```

## Style Guidelines

### PowerShell Style

- Use **PascalCase** for function names (`Invoke-JsonValidation`)
- Use **camelCase** for local variables
- Use **full cmdlet names** (not aliases) in scripts
- Include **comment-based help** for public functions
- Use **approved verbs** for function names

### Code Structure

```powershell
function Verb-Noun {
    <#
    .SYNOPSIS
        Brief description.
    .DESCRIPTION
        Detailed description.
    .PARAMETER Name
        Parameter description.
    .EXAMPLE
        Example usage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    # Implementation
}
```

### Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

Examples:
```
Add UUID format validation

Fix array uniqueItems validation for nested objects

Update README with custom validator examples

Closes #123
```

## Testing

- All new features must have corresponding tests
- All bug fixes should include a test that would have caught the bug
- Run `Invoke-Pester ./tests -Output Detailed` before submitting

### Test Structure

```powershell
Describe 'Feature Name' {
    Context 'Specific scenario' {
        It 'should do something specific' {
            # Arrange
            $schema = @{ type = 'string' }
            $input = '"test"'

            # Act
            $result = Invoke-JsonValidation -JsonInput $input -Schema $schema

            # Assert
            $result.IsValid | Should -BeTrue
        }
    }
}
```

## Adding New Features

### New Format Validators

1. Add the format to `ValidateFormat()` method in `JsonSchemaValidator`
2. Add corresponding tests
3. Update README documentation

### New Schema Properties

1. Add property handling in appropriate `Validate*()` method
2. Add tests covering valid and invalid cases
3. Update README with examples

## Questions?

Feel free to open an issue with the `question` label if you need help or clarification.

Thank you for contributing!
