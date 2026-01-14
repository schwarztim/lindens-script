# Linden's Script

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A collection of robust, enterprise-ready PowerShell tools for JSON validation and network flow evaluation.

## Tools Included

| Tool | Description |
|------|-------------|
| **JSON Schema Validator** | Dynamic JSON validation with comprehensive type checking |
| **Firewall Flow Evaluator** | PCI DSS compliance evaluation for network flows with DNS resolution and subnet support |

## Features

- **Dynamic Schema Validation** - Define schemas as hashtables or JSON files; no code changes needed for new fields
- **Comprehensive Type Support** - Validates `object`, `array`, `string`, `number`, `integer`, `boolean`, and `null`
- **Nested Structure Validation** - Recursively validates deeply nested objects and arrays
- **Format Validation** - Built-in validators for `email`, `uri`, `date`, `date-time`, `ipv4`, `ipv6`, `uuid`, `hostname`
- **Custom Validators** - Register scriptblocks for domain-specific business logic
- **Clear Error Reporting** - JSON path-based error messages for precise issue location
- **Extensible Architecture** - Add new fields without modifying source code

## Installation

### From Source

```powershell
git clone https://github.com/YOUR_USERNAME/lindens-script.git
cd lindens-script
. ./src/Invoke-JsonSchemaValidation.ps1
```

### Direct Import

```powershell
. /path/to/Invoke-JsonSchemaValidation.ps1
```

## Quick Start

### Basic Validation

```powershell
# Define a schema
$schema = @{
    type       = 'object'
    required   = @('id', 'name', 'email')
    properties = @{
        id    = @{ type = 'integer'; minimum = 1 }
        name  = @{ type = 'string'; minLength = 1 }
        email = @{ type = 'string'; format = 'email' }
    }
}

# Validate JSON
$json = '{"id": 1, "name": "John", "email": "john@example.com"}'
$result = Invoke-JsonValidation -JsonInput $json -Schema $schema

if ($result.IsValid) {
    Write-Host "Validation passed!"
    $result.ValidatedData  # Access parsed data
} else {
    Write-Host "Errors:"
    $result.Errors | ForEach-Object { Write-Host "  $_" }
}
```

### Using Schema Files

```powershell
# Load schema from JSON file
$result = Invoke-JsonValidation -JsonInput $json -SchemaPath './schemas/user.json'
```

### Quick Boolean Check

```powershell
if (Test-JsonSchema -JsonInput $json -Schema $schema) {
    # Valid JSON
}
```

## Schema Definition

### Supported Types

| Type | Description | Constraints |
|------|-------------|-------------|
| `string` | Text values | `minLength`, `maxLength`, `pattern`, `format` |
| `integer` | Whole numbers | `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf` |
| `number` | Decimal numbers | Same as integer |
| `boolean` | True/false | - |
| `array` | Lists | `minItems`, `maxItems`, `uniqueItems`, `items` |
| `object` | Key-value maps | `properties`, `required`, `additionalProperties`, `defaults` |
| `null` | Null value | - |

### Built-in Formats

| Format | Description | Example |
|--------|-------------|---------|
| `email` | Email address | `user@example.com` |
| `uri` | Valid URI | `https://example.com` |
| `date` | ISO 8601 date | `2024-01-15` |
| `date-time` | ISO 8601 datetime | `2024-01-15T10:30:00Z` |
| `ipv4` | IPv4 address | `192.168.1.1` |
| `ipv6` | IPv6 address | `::1` |
| `uuid` | UUID/GUID | `550e8400-e29b-41d4-a716-446655440000` |
| `hostname` | Valid hostname | `api.example.com` |

### Schema Examples

#### Object with Required Fields

```powershell
$schema = @{
    type       = 'object'
    required   = @('username', 'password')
    properties = @{
        username = @{
            type      = 'string'
            minLength = 3
            maxLength = 50
            pattern   = '^[a-zA-Z][a-zA-Z0-9_]*$'
        }
        password = @{
            type      = 'string'
            minLength = 8
        }
        remember = @{
            type = 'boolean'
        }
    }
    defaults = @{
        remember = $false
    }
}
```

#### Array with Item Validation

```powershell
$schema = @{
    type        = 'array'
    minItems    = 1
    maxItems    = 10
    uniqueItems = $true
    items       = @{
        type       = 'object'
        required   = @('id', 'value')
        properties = @{
            id    = @{ type = 'integer' }
            value = @{ type = 'string' }
        }
    }
}
```

#### Nested Objects

```powershell
$schema = @{
    type       = 'object'
    properties = @{
        user = @{
            type       = 'object'
            required   = @('name')
            properties = @{
                name    = @{ type = 'string' }
                profile = @{
                    type       = 'object'
                    properties = @{
                        bio     = @{ type = 'string'; maxLength = 500 }
                        website = @{ type = 'string'; format = 'uri' }
                    }
                }
            }
        }
    }
}
```

## Custom Validators

Register domain-specific validation logic:

```powershell
$customValidators = @{
    'corporate-email' = {
        param($value, $path)
        if ($value -notmatch '@company\.com$') {
            return "Must be a corporate email address"
        }
        return $null
    }

    'strong-password' = {
        param($value, $path)
        $errors = @()
        if ($value.Length -lt 12) { $errors += "minimum 12 characters" }
        if ($value -notmatch '[A-Z]') { $errors += "uppercase letter" }
        if ($value -notmatch '[a-z]') { $errors += "lowercase letter" }
        if ($value -notmatch '\d') { $errors += "digit" }
        if ($value -notmatch '[!@#$%^&*]') { $errors += "special character" }

        if ($errors.Count -gt 0) {
            return "Password requires: $($errors -join ', ')"
        }
        return $null
    }
}

$schema = @{
    type       = 'object'
    properties = @{
        email    = @{ type = 'string'; validator = 'corporate-email' }
        password = @{ type = 'string'; validator = 'strong-password' }
    }
}

$result = Invoke-JsonValidation -JsonInput $json -Schema $schema -CustomValidators $customValidators
```

## API Reference

### Invoke-JsonValidation

Main validation function with full result details.

```powershell
Invoke-JsonValidation
    -JsonInput <string>
    [-Schema <hashtable>]
    [-SchemaPath <string>]
    [-CustomValidators <hashtable>]
```

**Returns:** `ValidationResult` object with:
- `IsValid` (bool) - Whether validation passed
- `Errors` (string[]) - List of validation errors with JSON paths
- `Warnings` (string[]) - Non-critical warnings
- `ValidatedData` (hashtable) - Parsed data (if valid)

### Test-JsonSchema

Quick boolean validation check.

```powershell
Test-JsonSchema
    -JsonInput <string>
    -Schema <hashtable>
```

**Returns:** `$true` if valid, `$false` otherwise

### New-JsonSchema

Helper to create schema definitions programmatically.

```powershell
New-JsonSchema
    -Type <string>
    [-Properties <hashtable>]
    [-Required <string[]>]
    [-Items <hashtable>]
    [-Pattern <string>]
    [-Format <string>]
    [-Enum <array>]
    [-MinLength <int>]
    [-MaxLength <int>]
    [-MinItems <int>]
    [-MaxItems <int>]
    [-Minimum <double>]
    [-Maximum <double>]
    [-AdditionalProperties <bool>]
    [-Description <string>]
```

## Error Messages

Errors include JSON path notation for precise location:

```
[$.user.email] Value does not match format 'email'
[$.items[2].quantity] Value -5 is less than minimum 0
[$.settings.timeout] Expected type 'integer', got 'string'
[$.tags[3]] Duplicate item found (uniqueItems = true)
```

## Testing

Run the test suite with Pester:

```powershell
# Install Pester if needed
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run tests
Invoke-Pester ./tests -Output Detailed
```

---

## Firewall Flow Evaluator

An Azure Function for evaluating network firewall flows against PCI DSS compliance requirements.

### Features

- **Subnet/CIDR Support** - Pass CIDR notation (`10.0.0.0/24`) and automatically use the network start IP for lookups
- **Quiet DNS Failures** - Returns structured failure information instead of throwing exceptions
- **Hostname Resolution** - Resolves FQDNs and short hostnames with configurable suffix fallback
- **PCI Zone Detection** - Identifies CDE, CSE, and out-of-scope network segments
- **Batch Processing** - Evaluate multiple source/destination combinations in a single request
- **Risk Assessment** - Port-level risk analysis with high/medium/low categorization

### Input Formats

The evaluator accepts multiple input formats for source and destination:

| Format | Example | Behavior |
|--------|---------|----------|
| IPv4 Address | `192.168.1.100` | Used directly |
| CIDR Subnet | `10.0.0.0/24` | Extracts network start IP (`10.0.0.0`) |
| FQDN | `server.example.com` | DNS lookup |
| Short Hostname | `myserver` | Tries configured DNS suffixes |

### Quiet DNS Failure Response

When DNS resolution fails, instead of throwing an error, the API returns a structured response:

```json
{
  "evaluationStatus": "FAILED",
  "resolutionSuccess": false,
  "resolutionFailures": [
    {
      "side": "source",
      "input": "unknown-server",
      "error": "Unable to resolve short hostname...",
      "type": "DNS_SHORTNAME_FAILED",
      "tried": ["unknown-server.example.com", "unknown-server.corp.net"]
    }
  ]
}
```

### Subnet/CIDR Usage

When you pass a CIDR notation subnet, the evaluator:

1. Parses the CIDR to extract network address and prefix
2. Uses the **network start IP** for the Azure Search lookup
3. Includes subnet details in the resolution info

```json
{
  "srcInput": "10.0.1.0/24",
  "srcResolvedIp": "10.0.1.0",
  "srcResolution": {
    "type": "CIDR_SUBNET",
    "startIp": "10.0.1.0",
    "endIp": "10.0.1.255",
    "prefix": 24,
    "hostCount": 256,
    "note": "Using subnet start IP for search"
  }
}
```

### Example Request

```json
{
  "srcIp": "10.0.1.0/24",
  "dstIp": "192.168.100.50, webserver.corp.net",
  "protocol": "TCP",
  "srcPort": "any",
  "dstPort": "443, 8080",
  "context": "Web traffic to DMZ"
}
```

### Response Fields

| Field | Description |
|-------|-------------|
| `evaluationStatus` | `SUCCESS` or `FAILED` |
| `resolutionSuccess` | Whether all endpoints resolved |
| `resolutionFailures` | Details of any DNS failures |
| `pciScopeCategory` | `CDE_SCOPE`, `CSE_CONNECTED`, or `OUT_OF_SCOPE` |
| `hardBlock` | Whether the flow is explicitly disallowed |
| `flowBoundary` | Direction of flow (e.g., `TO_CDE`, `FROM_CSE`) |
| `portRiskLevel` | `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN` |

---

## Project Structure

```
lindens-script/
├── src/
│   ├── Invoke-JsonSchemaValidation.ps1    # JSON Schema Validator
│   └── Invoke-FirewallFlowEvaluation.ps1  # Firewall Flow Evaluator (Azure Function)
├── examples/
│   ├── basic-usage.ps1                     # Usage examples
│   └── user-schema.json                    # Sample schema
├── tests/
│   └── Invoke-JsonSchemaValidation.Tests.ps1
├── .github/
│   └── workflows/
│       └── ci.yml                          # GitHub Actions CI
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [JSON Schema](https://json-schema.org/) specification
- Built with PowerShell best practices

---

**Linden's Script** - Robust JSON validation for PowerShell
