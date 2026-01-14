#Requires -Version 5.1

<#
.SYNOPSIS
    Basic usage examples for Linden's Script JSON Schema Validator.

.DESCRIPTION
    Demonstrates common validation scenarios including basic validation,
    custom validators, and error handling.
#>

# Import the module
. "$PSScriptRoot/../src/Invoke-JsonSchemaValidation.ps1"

Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  Linden's Script - JSON Schema Validator Examples" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

#region Example 1: Basic Object Validation

Write-Host "`n[Example 1] Basic Object Validation" -ForegroundColor Yellow
Write-Host "-" * 40

$userSchema = @{
    type       = 'object'
    required   = @('id', 'username', 'email')
    properties = @{
        id       = @{ type = 'integer'; minimum = 1 }
        username = @{ type = 'string'; minLength = 3; maxLength = 50 }
        email    = @{ type = 'string'; format = 'email' }
        age      = @{ type = 'integer'; minimum = 0; maximum = 150 }
    }
}

$validUser = @'
{
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com",
    "age": 28
}
'@

$result = Invoke-JsonValidation -JsonInput $validUser -Schema $userSchema

Write-Host "Input: Valid user object"
Write-Host "Result: " -NoNewline
if ($result.IsValid) {
    Write-Host "PASSED" -ForegroundColor Green
}
else {
    Write-Host "FAILED" -ForegroundColor Red
    $result.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

#endregion

#region Example 2: Validation with Errors

Write-Host "`n[Example 2] Validation with Errors" -ForegroundColor Yellow
Write-Host "-" * 40

$invalidUser = @'
{
    "id": -5,
    "username": "ab",
    "email": "not-an-email",
    "age": 200
}
'@

$result = Invoke-JsonValidation -JsonInput $invalidUser -Schema $userSchema

Write-Host "Input: Invalid user object (multiple errors)"
Write-Host "Result: " -NoNewline
if ($result.IsValid) {
    Write-Host "PASSED" -ForegroundColor Green
}
else {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host "Errors found:"
    $result.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

#endregion

#region Example 3: Nested Object Validation

Write-Host "`n[Example 3] Nested Object Validation" -ForegroundColor Yellow
Write-Host "-" * 40

$profileSchema = @{
    type       = 'object'
    required   = @('user')
    properties = @{
        user = @{
            type       = 'object'
            required   = @('name')
            properties = @{
                name    = @{ type = 'string' }
                contact = @{
                    type       = 'object'
                    properties = @{
                        email = @{ type = 'string'; format = 'email' }
                        phone = @{ type = 'string'; pattern = '^\+?[\d\s-]+$' }
                    }
                }
            }
        }
    }
}

$nestedData = @'
{
    "user": {
        "name": "Jane Smith",
        "contact": {
            "email": "jane@example.com",
            "phone": "+1 555-123-4567"
        }
    }
}
'@

$result = Invoke-JsonValidation -JsonInput $nestedData -Schema $profileSchema

Write-Host "Input: Nested user profile"
Write-Host "Result: " -NoNewline
if ($result.IsValid) {
    Write-Host "PASSED" -ForegroundColor Green
}
else {
    Write-Host "FAILED" -ForegroundColor Red
}

#endregion

#region Example 4: Array Validation

Write-Host "`n[Example 4] Array Validation" -ForegroundColor Yellow
Write-Host "-" * 40

$tagsSchema = @{
    type        = 'array'
    minItems    = 1
    maxItems    = 5
    uniqueItems = $true
    items       = @{
        type      = 'string'
        minLength = 2
    }
}

$validTags = '["powershell", "automation", "devops"]'
$invalidTags = '["ps", "ps", "x"]'  # Duplicate and too short

$result1 = Invoke-JsonValidation -JsonInput $validTags -Schema $tagsSchema
$result2 = Invoke-JsonValidation -JsonInput $invalidTags -Schema $tagsSchema

Write-Host "Valid tags array: " -NoNewline
Write-Host $(if ($result1.IsValid) { "PASSED" } else { "FAILED" }) -ForegroundColor $(if ($result1.IsValid) { "Green" } else { "Red" })

Write-Host "Invalid tags array: " -NoNewline
Write-Host $(if ($result2.IsValid) { "PASSED" } else { "FAILED" }) -ForegroundColor $(if ($result2.IsValid) { "Green" } else { "Red" })
if (-not $result2.IsValid) {
    $result2.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

#endregion

#region Example 5: Custom Validators

Write-Host "`n[Example 5] Custom Validators" -ForegroundColor Yellow
Write-Host "-" * 40

$schemaWithCustom = @{
    type       = 'object'
    properties = @{
        email = @{
            type      = 'string'
            validator = 'corporate-email'
        }
        password = @{
            type      = 'string'
            validator = 'strong-password'
        }
    }
}

$customValidators = @{
    'corporate-email' = {
        param($value, $path)
        if ($value -notmatch '@(company\.com|corp\.net)$') {
            return "Must be a corporate email address"
        }
        return $null
    }
    'strong-password' = {
        param($value, $path)
        $errors = @()
        if ($value.Length -lt 8) { $errors += "at least 8 characters" }
        if ($value -notmatch '[A-Z]') { $errors += "an uppercase letter" }
        if ($value -notmatch '[a-z]') { $errors += "a lowercase letter" }
        if ($value -notmatch '\d') { $errors += "a number" }
        if ($errors.Count -gt 0) {
            return "Password must contain: $($errors -join ', ')"
        }
        return $null
    }
}

$testData = @'
{
    "email": "user@company.com",
    "password": "SecurePass123"
}
'@

$result = Invoke-JsonValidation -JsonInput $testData -Schema $schemaWithCustom -CustomValidators $customValidators

Write-Host "Custom validator test: " -NoNewline
Write-Host $(if ($result.IsValid) { "PASSED" } else { "FAILED" }) -ForegroundColor $(if ($result.IsValid) { "Green" } else { "Red" })

#endregion

#region Example 6: Schema from File

Write-Host "`n[Example 6] Schema from File" -ForegroundColor Yellow
Write-Host "-" * 40

$schemaPath = "$PSScriptRoot/user-schema.json"

if (Test-Path $schemaPath) {
    $fileTestData = @'
{
    "id": 42,
    "username": "linden_dev",
    "email": "linden@example.com",
    "role": "admin",
    "tags": ["developer", "lead"],
    "profile": {
        "firstName": "Linden",
        "lastName": "Script"
    }
}
'@

    $result = Invoke-JsonValidation -JsonInput $fileTestData -SchemaPath $schemaPath

    Write-Host "Schema file validation: " -NoNewline
    Write-Host $(if ($result.IsValid) { "PASSED" } else { "FAILED" }) -ForegroundColor $(if ($result.IsValid) { "Green" } else { "Red" })
}
else {
    Write-Host "Schema file not found at: $schemaPath" -ForegroundColor Yellow
}

#endregion

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "  Examples completed!" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
