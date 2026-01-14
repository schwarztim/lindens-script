#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Invoke-JsonSchemaValidation module.

.DESCRIPTION
    Comprehensive test suite covering all validation scenarios
    including types, formats, nested objects, arrays, and custom validators.
#>

BeforeAll {
    . "$PSScriptRoot/../src/Invoke-JsonSchemaValidation.ps1"
}

Describe 'Invoke-JsonValidation' {

    Context 'Basic Type Validation' {

        It 'validates string type correctly' {
            $schema = @{ type = 'string' }
            $result = Invoke-JsonValidation -JsonInput '"hello"' -Schema $schema
            $result.IsValid | Should -BeTrue
        }

        It 'validates integer type correctly' {
            $schema = @{ type = 'integer' }
            $result = Invoke-JsonValidation -JsonInput '42' -Schema $schema
            $result.IsValid | Should -BeTrue
        }

        It 'validates number type correctly' {
            $schema = @{ type = 'number' }
            $result = Invoke-JsonValidation -JsonInput '3.14' -Schema $schema
            $result.IsValid | Should -BeTrue
        }

        It 'validates boolean type correctly' {
            $schema = @{ type = 'boolean' }
            $result = Invoke-JsonValidation -JsonInput 'true' -Schema $schema
            $result.IsValid | Should -BeTrue
        }

        It 'validates array type correctly' {
            $schema = @{ type = 'array' }
            $result = Invoke-JsonValidation -JsonInput '[1, 2, 3]' -Schema $schema
            $result.IsValid | Should -BeTrue
        }

        It 'validates object type correctly' {
            $schema = @{ type = 'object' }
            $result = Invoke-JsonValidation -JsonInput '{"key": "value"}' -Schema $schema
            $result.IsValid | Should -BeTrue
        }

        It 'fails on type mismatch' {
            $schema = @{ type = 'string' }
            $result = Invoke-JsonValidation -JsonInput '123' -Schema $schema
            $result.IsValid | Should -BeFalse
            $result.Errors | Should -HaveCount 1
        }
    }

    Context 'String Validation' {

        It 'validates minLength constraint' {
            $schema = @{ type = 'string'; minLength = 5 }

            $valid = Invoke-JsonValidation -JsonInput '"hello"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"hi"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates maxLength constraint' {
            $schema = @{ type = 'string'; maxLength = 5 }

            $valid = Invoke-JsonValidation -JsonInput '"hello"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"hello world"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates pattern constraint' {
            $schema = @{ type = 'string'; pattern = '^[A-Z]{3}\d{3}$' }

            $valid = Invoke-JsonValidation -JsonInput '"ABC123"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"abc123"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }
    }

    Context 'Number Validation' {

        It 'validates minimum constraint' {
            $schema = @{ type = 'integer'; minimum = 10 }

            $valid = Invoke-JsonValidation -JsonInput '15' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '5' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates maximum constraint' {
            $schema = @{ type = 'integer'; maximum = 100 }

            $valid = Invoke-JsonValidation -JsonInput '50' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '150' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates exclusiveMinimum constraint' {
            $schema = @{ type = 'integer'; exclusiveMinimum = 10 }

            $valid = Invoke-JsonValidation -JsonInput '11' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '10' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates multipleOf constraint' {
            $schema = @{ type = 'integer'; multipleOf = 5 }

            $valid = Invoke-JsonValidation -JsonInput '15' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '13' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }
    }

    Context 'Format Validation' {

        It 'validates email format' {
            $schema = @{ type = 'string'; format = 'email' }

            $valid = Invoke-JsonValidation -JsonInput '"test@example.com"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"not-an-email"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates uri format' {
            $schema = @{ type = 'string'; format = 'uri' }

            $valid = Invoke-JsonValidation -JsonInput '"https://example.com"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"not a url"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates date format' {
            $schema = @{ type = 'string'; format = 'date' }

            $valid = Invoke-JsonValidation -JsonInput '"2024-01-15"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"15/01/2024"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates uuid format' {
            $schema = @{ type = 'string'; format = 'uuid' }

            $valid = Invoke-JsonValidation -JsonInput '"550e8400-e29b-41d4-a716-446655440000"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"not-a-uuid"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates ipv4 format' {
            $schema = @{ type = 'string'; format = 'ipv4' }

            $valid = Invoke-JsonValidation -JsonInput '"192.168.1.1"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"999.999.999.999"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }
    }

    Context 'Object Validation' {

        It 'validates required fields' {
            $schema = @{
                type       = 'object'
                required   = @('name', 'email')
                properties = @{
                    name  = @{ type = 'string' }
                    email = @{ type = 'string' }
                }
            }

            $valid = Invoke-JsonValidation -JsonInput '{"name":"test","email":"test@test.com"}' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '{"name":"test"}' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates nested objects' {
            $schema = @{
                type       = 'object'
                properties = @{
                    user = @{
                        type       = 'object'
                        properties = @{
                            name = @{ type = 'string' }
                        }
                    }
                }
            }

            $json = '{"user":{"name":"test"}}'
            $result = Invoke-JsonValidation -JsonInput $json -Schema $schema

            $result.IsValid | Should -BeTrue
        }

        It 'rejects additional properties when disabled' {
            $schema = @{
                type                 = 'object'
                additionalProperties = $false
                properties           = @{
                    name = @{ type = 'string' }
                }
            }

            $valid = Invoke-JsonValidation -JsonInput '{"name":"test"}' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '{"name":"test","extra":"field"}' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }
    }

    Context 'Array Validation' {

        It 'validates minItems constraint' {
            $schema = @{ type = 'array'; minItems = 2 }

            $valid = Invoke-JsonValidation -JsonInput '[1, 2, 3]' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '[1]' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates maxItems constraint' {
            $schema = @{ type = 'array'; maxItems = 3 }

            $valid = Invoke-JsonValidation -JsonInput '[1, 2]' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '[1, 2, 3, 4]' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates uniqueItems constraint' {
            $schema = @{ type = 'array'; uniqueItems = $true }

            $valid = Invoke-JsonValidation -JsonInput '[1, 2, 3]' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '[1, 2, 2]' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'validates array item schema' {
            $schema = @{
                type  = 'array'
                items = @{ type = 'string'; minLength = 2 }
            }

            $valid = Invoke-JsonValidation -JsonInput '["ab", "cd"]' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '["a", "b"]' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }
    }

    Context 'Enum Validation' {

        It 'validates enum values' {
            $schema = @{
                type = 'string'
                enum = @('red', 'green', 'blue')
            }

            $valid = Invoke-JsonValidation -JsonInput '"red"' -Schema $schema
            $invalid = Invoke-JsonValidation -JsonInput '"yellow"' -Schema $schema

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }
    }

    Context 'Custom Validators' {

        It 'executes custom validator' {
            $schema = @{
                type      = 'string'
                validator = 'no-spaces'
            }

            $customValidators = @{
                'no-spaces' = {
                    param($value, $path)
                    if ($value -match '\s') { return "Value cannot contain spaces" }
                    return $null
                }
            }

            $valid = Invoke-JsonValidation -JsonInput '"nospaces"' -Schema $schema -CustomValidators $customValidators
            $invalid = Invoke-JsonValidation -JsonInput '"has spaces"' -Schema $schema -CustomValidators $customValidators

            $valid.IsValid | Should -BeTrue
            $invalid.IsValid | Should -BeFalse
        }

        It 'warns on unknown validator' {
            $schema = @{
                type      = 'string'
                validator = 'unknown-validator'
            }

            $result = Invoke-JsonValidation -JsonInput '"test"' -Schema $schema

            $result.IsValid | Should -BeTrue
            $result.Warnings | Should -HaveCount 1
        }
    }

    Context 'Error Handling' {

        It 'handles invalid JSON gracefully' {
            $schema = @{ type = 'object' }
            $result = Invoke-JsonValidation -JsonInput 'not valid json' -Schema $schema

            $result.IsValid | Should -BeFalse
            $result.Errors[0] | Should -Match 'Invalid JSON'
        }

        It 'provides path information in errors' {
            $schema = @{
                type       = 'object'
                properties = @{
                    nested = @{
                        type       = 'object'
                        properties = @{
                            value = @{ type = 'string' }
                        }
                    }
                }
            }

            $result = Invoke-JsonValidation -JsonInput '{"nested":{"value":123}}' -Schema $schema

            $result.IsValid | Should -BeFalse
            $result.Errors[0] | Should -Match '\$\.nested\.value'
        }
    }
}

Describe 'New-JsonSchema' {

    It 'creates basic schema' {
        $schema = New-JsonSchema -Type 'string' -MinLength 5 -MaxLength 10

        $schema.type | Should -Be 'string'
        $schema.minLength | Should -Be 5
        $schema.maxLength | Should -Be 10
    }

    It 'creates object schema with properties' {
        $schema = New-JsonSchema -Type 'object' -Properties @{
            name = @{ type = 'string' }
        } -Required @('name')

        $schema.type | Should -Be 'object'
        $schema.required | Should -Contain 'name'
        $schema.properties.name.type | Should -Be 'string'
    }
}

Describe 'Test-JsonSchema' {

    It 'returns true for valid JSON' {
        $schema = @{ type = 'string' }
        $result = Test-JsonSchema -JsonInput '"valid"' -Schema $schema

        $result | Should -BeTrue
    }

    It 'returns false for invalid JSON' {
        $schema = @{ type = 'string' }
        $result = Test-JsonSchema -JsonInput '123' -Schema $schema

        $result | Should -BeFalse
    }
}
