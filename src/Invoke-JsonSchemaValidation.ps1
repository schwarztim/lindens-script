#Requires -Version 5.1

<#
.SYNOPSIS
    Validates JSON input against a dynamically defined schema.

.DESCRIPTION
    A robust PowerShell JSON schema validator that accepts JSON input and validates
    it against a schema definition. Supports nested objects, arrays, optional fields,
    custom validators, format validation, and extensible schema definitions.

.PARAMETER JsonInput
    The JSON string to validate.

.PARAMETER Schema
    The schema definition hashtable.

.PARAMETER SchemaPath
    Path to a JSON file containing the schema definition.

.PARAMETER CustomValidators
    Hashtable of custom validator scriptblocks for domain-specific validation.

.EXAMPLE
    $result = Invoke-JsonValidation -JsonInput $json -Schema $schema
    if ($result.IsValid) { Write-Host "Valid!" }

.EXAMPLE
    $result = '{"name": "test"}' | Invoke-JsonValidation -SchemaPath ./schema.json

.NOTES
    Author: Linden
    Version: 1.0.0
    License: MIT

.LINK
    https://github.com/lindens-script
#>

#region Classes

class ValidationResult {
    [bool]$IsValid
    [string[]]$Errors
    [string[]]$Warnings
    [hashtable]$ValidatedData

    ValidationResult() {
        $this.IsValid = $true
        $this.Errors = @()
        $this.Warnings = @()
        $this.ValidatedData = @{}
    }

    [void] AddError([string]$path, [string]$message) {
        $this.IsValid = $false
        $this.Errors += "[$path] $message"
    }

    [void] AddWarning([string]$path, [string]$message) {
        $this.Warnings += "[$path] $message"
    }

    [string] ToString() {
        if ($this.IsValid) {
            return "Validation passed with $($this.Warnings.Count) warning(s)"
        }
        return "Validation failed with $($this.Errors.Count) error(s)"
    }
}

class JsonSchemaValidator {
    [hashtable]$Schema
    [hashtable]$CustomValidators
    [bool]$StrictMode

    JsonSchemaValidator([hashtable]$schema) {
        $this.Schema = $schema
        $this.CustomValidators = @{}
        $this.StrictMode = $false
    }

    [void] RegisterValidator([string]$name, [scriptblock]$validator) {
        $this.CustomValidators[$name] = $validator
    }

    [ValidationResult] Validate([string]$jsonInput) {
        $result = [ValidationResult]::new()

        # Parse JSON
        try {
            $data = $jsonInput | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        }
        catch {
            $result.AddError('$', "Invalid JSON: $($_.Exception.Message)")
            return $result
        }

        # Validate against schema
        $this.ValidateNode($data, $this.Schema, '$', $result)

        if ($result.IsValid) {
            $result.ValidatedData = $data
        }

        return $result
    }

    hidden [void] ValidateNode($data, [hashtable]$schema, [string]$path, [ValidationResult]$result) {
        # Handle null data
        if ($null -eq $data) {
            if ($schema.required -eq $true) {
                $result.AddError($path, "Required value is null")
            }
            return
        }

        # Validate type
        if ($schema.ContainsKey('type')) {
            $typeValid = $this.ValidateType($data, $schema.type, $path, $result)
            if (-not $typeValid) { return }
        }

        # Type-specific validation
        switch ($schema.type) {
            'object'  { $this.ValidateObject($data, $schema, $path, $result) }
            'array'   { $this.ValidateArray($data, $schema, $path, $result) }
            'string'  { $this.ValidateString($data, $schema, $path, $result) }
            'number'  { $this.ValidateNumber($data, $schema, $path, $result) }
            'integer' { $this.ValidateInteger($data, $schema, $path, $result) }
            'boolean' { <# Type check is sufficient #> }
        }

        # Enum validation
        if ($schema.ContainsKey('enum')) {
            if ($data -notin $schema.enum) {
                $allowed = $schema.enum -join ', '
                $result.AddError($path, "Value '$data' not in allowed values: $allowed")
            }
        }

        # Custom validator
        if ($schema.ContainsKey('validator')) {
            $validatorName = $schema.validator
            if ($this.CustomValidators.ContainsKey($validatorName)) {
                $customResult = & $this.CustomValidators[$validatorName] $data $path
                if ($customResult -is [string] -and $customResult) {
                    $result.AddError($path, $customResult)
                }
            }
            else {
                $result.AddWarning($path, "Unknown validator: $validatorName")
            }
        }

        # Pattern validation for strings
        if ($schema.ContainsKey('pattern') -and $data -is [string]) {
            if ($data -notmatch $schema.pattern) {
                $result.AddError($path, "Value does not match pattern: $($schema.pattern)")
            }
        }
    }

    hidden [bool] ValidateType($data, [string]$expectedType, [string]$path, [ValidationResult]$result) {
        $actualType = $this.GetJsonType($data)

        # Handle multiple allowed types (e.g., "string|null")
        $allowedTypes = $expectedType -split '\|'

        if ($actualType -notin $allowedTypes) {
            $result.AddError($path, "Expected type '$expectedType', got '$actualType'")
            return $false
        }
        return $true
    }

    hidden [string] GetJsonType($data) {
        if ($null -eq $data) { return 'null' }
        if ($data -is [bool]) { return 'boolean' }
        if ($data -is [int] -or $data -is [long]) { return 'integer' }
        if ($data -is [double] -or $data -is [decimal] -or $data -is [float]) { return 'number' }
        if ($data -is [string]) { return 'string' }
        if ($data -is [array] -or $data -is [System.Collections.ArrayList]) { return 'array' }
        if ($data -is [hashtable] -or $data -is [System.Collections.Specialized.OrderedDictionary]) { return 'object' }
        return 'unknown'
    }

    hidden [void] ValidateObject([hashtable]$data, [hashtable]$schema, [string]$path, [ValidationResult]$result) {
        $properties = $schema.properties
        $requiredFields = $schema.required
        $additionalProperties = $schema.additionalProperties

        if ($null -eq $properties) { $properties = @{} }
        if ($null -eq $requiredFields) { $requiredFields = @() }
        if ($null -eq $additionalProperties) { $additionalProperties = $true }

        # Check required fields
        foreach ($field in $requiredFields) {
            if (-not $data.ContainsKey($field)) {
                $result.AddError("$path.$field", "Required field is missing")
            }
        }

        # Validate each property
        foreach ($key in $data.Keys) {
            $fieldPath = "$path.$key"

            if ($properties.ContainsKey($key)) {
                $this.ValidateNode($data[$key], $properties[$key], $fieldPath, $result)
            }
            elseif ($additionalProperties -eq $false) {
                $result.AddError($fieldPath, "Unexpected property (additionalProperties = false)")
            }
            elseif ($additionalProperties -is [hashtable]) {
                # Validate against additionalProperties schema
                $this.ValidateNode($data[$key], $additionalProperties, $fieldPath, $result)
            }
        }

        # Apply defaults for missing optional fields
        if ($schema.ContainsKey('defaults')) {
            foreach ($defaultKey in $schema.defaults.Keys) {
                if (-not $data.ContainsKey($defaultKey)) {
                    $data[$defaultKey] = $schema.defaults[$defaultKey]
                }
            }
        }
    }

    hidden [void] ValidateArray($data, [hashtable]$schema, [string]$path, [ValidationResult]$result) {
        # Min/max items validation
        if ($schema.ContainsKey('minItems') -and $data.Count -lt $schema.minItems) {
            $result.AddError($path, "Array has $($data.Count) items, minimum is $($schema.minItems)")
        }
        if ($schema.ContainsKey('maxItems') -and $data.Count -gt $schema.maxItems) {
            $result.AddError($path, "Array has $($data.Count) items, maximum is $($schema.maxItems)")
        }

        # Validate each item
        if ($schema.ContainsKey('items')) {
            for ($i = 0; $i -lt $data.Count; $i++) {
                $this.ValidateNode($data[$i], $schema.items, "$path[$i]", $result)
            }
        }

        # Unique items validation
        if ($schema.uniqueItems -eq $true) {
            $seen = @{}
            for ($i = 0; $i -lt $data.Count; $i++) {
                $key = $data[$i] | ConvertTo-Json -Compress
                if ($seen.ContainsKey($key)) {
                    $result.AddError("$path[$i]", "Duplicate item found (uniqueItems = true)")
                }
                $seen[$key] = $true
            }
        }
    }

    hidden [void] ValidateString($data, [hashtable]$schema, [string]$path, [ValidationResult]$result) {
        if ($schema.ContainsKey('minLength') -and $data.Length -lt $schema.minLength) {
            $result.AddError($path, "String length $($data.Length) is less than minimum $($schema.minLength)")
        }
        if ($schema.ContainsKey('maxLength') -and $data.Length -gt $schema.maxLength) {
            $result.AddError($path, "String length $($data.Length) exceeds maximum $($schema.maxLength)")
        }

        # Format validation
        if ($schema.ContainsKey('format')) {
            $this.ValidateFormat($data, $schema.format, $path, $result)
        }
    }

    hidden [void] ValidateNumber($data, [hashtable]$schema, [string]$path, [ValidationResult]$result) {
        if ($schema.ContainsKey('minimum') -and $data -lt $schema.minimum) {
            $result.AddError($path, "Value $data is less than minimum $($schema.minimum)")
        }
        if ($schema.ContainsKey('maximum') -and $data -gt $schema.maximum) {
            $result.AddError($path, "Value $data exceeds maximum $($schema.maximum)")
        }
        if ($schema.ContainsKey('exclusiveMinimum') -and $data -le $schema.exclusiveMinimum) {
            $result.AddError($path, "Value $data must be greater than $($schema.exclusiveMinimum)")
        }
        if ($schema.ContainsKey('exclusiveMaximum') -and $data -ge $schema.exclusiveMaximum) {
            $result.AddError($path, "Value $data must be less than $($schema.exclusiveMaximum)")
        }
        if ($schema.ContainsKey('multipleOf') -and ($data % $schema.multipleOf) -ne 0) {
            $result.AddError($path, "Value $data is not a multiple of $($schema.multipleOf)")
        }
    }

    hidden [void] ValidateInteger($data, [hashtable]$schema, [string]$path, [ValidationResult]$result) {
        $this.ValidateNumber($data, $schema, $path, $result)
    }

    hidden [void] ValidateFormat([string]$data, [string]$format, [string]$path, [ValidationResult]$result) {
        $valid = $true
        switch ($format) {
            'email' {
                $valid = $data -match '^[^@\s]+@[^@\s]+\.[^@\s]+$'
            }
            'uri' {
                $valid = [Uri]::IsWellFormedUriString($data, [UriKind]::Absolute)
            }
            'date' {
                $valid = $data -match '^\d{4}-\d{2}-\d{2}$' -and [datetime]::TryParse($data, [ref]$null)
            }
            'date-time' {
                $valid = [datetime]::TryParse($data, [ref]$null)
            }
            'ipv4' {
                $valid = $data -match '^(\d{1,3}\.){3}\d{1,3}$' -and
                         ([ipaddress]::TryParse($data, [ref]$null))
            }
            'ipv6' {
                try {
                    $ip = [ipaddress]::Parse($data)
                    $valid = $ip.AddressFamily -eq 'InterNetworkV6'
                }
                catch { $valid = $false }
            }
            'uuid' {
                $valid = $data -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
            }
            'hostname' {
                $valid = $data -match '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            }
            default {
                $result.AddWarning($path, "Unknown format: $format")
                return
            }
        }
        if (-not $valid) {
            $result.AddError($path, "Value does not match format '$format'")
        }
    }
}

#endregion

#region Public Functions

function Invoke-JsonValidation {
    <#
    .SYNOPSIS
        Validates JSON input against a schema definition.

    .DESCRIPTION
        Main entry point for JSON schema validation. Accepts JSON as string input
        and validates against either a hashtable schema or a schema file.

    .PARAMETER JsonInput
        The JSON string to validate. Accepts pipeline input.

    .PARAMETER Schema
        A hashtable containing the schema definition.

    .PARAMETER SchemaPath
        Path to a JSON file containing the schema definition.

    .PARAMETER CustomValidators
        Hashtable of custom validator scriptblocks.

    .OUTPUTS
        ValidationResult object with IsValid, Errors, Warnings, and ValidatedData properties.

    .EXAMPLE
        $result = Invoke-JsonValidation -JsonInput '{"name":"test"}' -Schema $schema

    .EXAMPLE
        Get-Content data.json | Invoke-JsonValidation -SchemaPath schema.json
    #>
    [CmdletBinding()]
    [OutputType([ValidationResult])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$JsonInput,

        [Parameter(Mandatory, ParameterSetName = 'Schema')]
        [hashtable]$Schema,

        [Parameter(Mandatory, ParameterSetName = 'SchemaFile')]
        [ValidateScript({ Test-Path $_ })]
        [string]$SchemaPath,

        [Parameter()]
        [hashtable]$CustomValidators = @{}
    )

    process {
        # Load schema from file if path provided
        if ($PSCmdlet.ParameterSetName -eq 'SchemaFile') {
            try {
                $Schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json -AsHashtable
            }
            catch {
                throw "Failed to load schema from '$SchemaPath': $($_.Exception.Message)"
            }
        }

        # Create validator instance
        $validator = [JsonSchemaValidator]::new($Schema)

        # Register custom validators
        foreach ($name in $CustomValidators.Keys) {
            $validator.RegisterValidator($name, $CustomValidators[$name])
        }

        # Validate and return result
        return $validator.Validate($JsonInput)
    }
}

function New-JsonSchema {
    <#
    .SYNOPSIS
        Creates a new JSON schema definition.

    .DESCRIPTION
        Helper function to programmatically create schema definitions
        with proper structure and validation rules.

    .PARAMETER Type
        The JSON type for the schema root (object, array, string, number, integer, boolean, null).

    .PARAMETER Properties
        Hashtable of property definitions for object types.

    .PARAMETER Required
        Array of required property names.

    .OUTPUTS
        Hashtable containing the schema definition.

    .EXAMPLE
        $schema = New-JsonSchema -Type 'object' -Properties @{ name = @{ type = 'string' } } -Required @('name')
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('object', 'array', 'string', 'number', 'integer', 'boolean', 'null')]
        [string]$Type,

        [Parameter()]
        [hashtable]$Properties,

        [Parameter()]
        [string[]]$Required,

        [Parameter()]
        [hashtable]$Items,

        [Parameter()]
        [string]$Pattern,

        [Parameter()]
        [string]$Format,

        [Parameter()]
        [array]$Enum,

        [Parameter()]
        [int]$MinLength,

        [Parameter()]
        [int]$MaxLength,

        [Parameter()]
        [int]$MinItems,

        [Parameter()]
        [int]$MaxItems,

        [Parameter()]
        [double]$Minimum,

        [Parameter()]
        [double]$Maximum,

        [Parameter()]
        [bool]$AdditionalProperties = $true,

        [Parameter()]
        [string]$Description
    )

    $schema = @{ type = $Type }

    if ($Properties) { $schema.properties = $Properties }
    if ($Required) { $schema.required = $Required }
    if ($Items) { $schema.items = $Items }
    if ($Pattern) { $schema.pattern = $Pattern }
    if ($Format) { $schema.format = $Format }
    if ($Enum) { $schema.enum = $Enum }
    if ($PSBoundParameters.ContainsKey('MinLength')) { $schema.minLength = $MinLength }
    if ($PSBoundParameters.ContainsKey('MaxLength')) { $schema.maxLength = $MaxLength }
    if ($PSBoundParameters.ContainsKey('MinItems')) { $schema.minItems = $MinItems }
    if ($PSBoundParameters.ContainsKey('MaxItems')) { $schema.maxItems = $MaxItems }
    if ($PSBoundParameters.ContainsKey('Minimum')) { $schema.minimum = $Minimum }
    if ($PSBoundParameters.ContainsKey('Maximum')) { $schema.maximum = $Maximum }
    if (-not $AdditionalProperties) { $schema.additionalProperties = $false }
    if ($Description) { $schema.description = $Description }

    return $schema
}

function Test-JsonSchema {
    <#
    .SYNOPSIS
        Quick validation check returning boolean result.

    .DESCRIPTION
        Convenience function that returns $true if JSON is valid, $false otherwise.

    .PARAMETER JsonInput
        The JSON string to validate.

    .PARAMETER Schema
        The schema definition hashtable.

    .OUTPUTS
        Boolean indicating validation success.

    .EXAMPLE
        if (Test-JsonSchema -JsonInput $json -Schema $schema) { "Valid!" }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$JsonInput,

        [Parameter(Mandatory)]
        [hashtable]$Schema
    )

    process {
        $result = Invoke-JsonValidation -JsonInput $JsonInput -Schema $Schema
        return $result.IsValid
    }
}

#endregion

#region Module Export

# Export public functions when loaded as module
Export-ModuleMember -Function @(
    'Invoke-JsonValidation'
    'New-JsonSchema'
    'Test-JsonSchema'
)

#endregion
