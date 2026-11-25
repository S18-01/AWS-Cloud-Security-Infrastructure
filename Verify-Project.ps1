$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (!(Test-Path .\security-pipeline\main.tf.json -PathType Leaf)) {
        throw 'Terraform configuration is missing. Extract the complete ZIP.'
    }
    python -B -m unittest discover -s .\security-pipeline -v
    if ($LASTEXITCODE -ne 0) { throw 'Python tests failed.' }
    terraform '-chdir=security-pipeline' init '-backend=false'
    if ($LASTEXITCODE -ne 0) { throw 'Terraform initialization failed.' }
    terraform '-chdir=security-pipeline' validate
    if ($LASTEXITCODE -ne 0) { throw 'Terraform validation failed.' }
} finally {
    Pop-Location
}
