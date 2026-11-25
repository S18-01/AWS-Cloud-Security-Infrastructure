$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (!(Test-Path .\security-pipeline\main.tf.json -PathType Leaf)) {
        throw 'Terraform configuration is missing.'
    }
    aws sts get-caller-identity --region us-east-1 --output table --no-cli-pager
    if ($LASTEXITCODE -ne 0) { throw 'AWS authentication failed.' }
    terraform '-chdir=security-pipeline' init
    if ($LASTEXITCODE -ne 0) { throw 'Terraform initialization failed.' }
    terraform '-chdir=security-pipeline' plan '-var=region=us-east-1' '-out=demo.tfplan'
    if ($LASTEXITCODE -ne 0) { throw 'Terraform planning failed.' }
    if ((Read-Host 'Review the account and plan, then type deploy to provision the demo') -cne 'deploy') { return }
    terraform '-chdir=security-pipeline' apply demo.tfplan
    if ($LASTEXITCODE -ne 0) { throw 'Apply failed. Check Terraform state for partially created resources.' }
    $table = terraform '-chdir=security-pipeline' output -raw findings_table
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the findings table name.' }
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        $json = aws dynamodb scan --table-name $table --consistent-read --region us-east-1 --output json --no-cli-pager
        if ($LASTEXITCODE -ne 0) { throw 'Could not read the findings table.' }
        $result = ($json -join "`n") | ConvertFrom-Json
        if ($result.Count -gt 0) {
            $item = $result.Items[0]
            if ($result.Count -ne 1 -or $item.source_ip.S -ne '192.0.2.10' -or $item.failed_attempts.N -ne '5' -or $item.severity.S -ne 'MEDIUM') {
                throw 'The findings table did not match the expected demo result.'
            }
            $item | ConvertTo-Json -Depth 8
            $group = terraform '-chdir=security-pipeline' output -raw detector_log_group
            if ($LASTEXITCODE -ne 0) { throw 'Finding verified but the log group lookup failed.' }
            aws logs tail $group --region us-east-1 --since 30m --no-cli-pager
            if ($LASTEXITCODE -ne 0) { throw 'Finding verified but CloudWatch log retrieval failed.' }
            Write-Host 'Verified one MEDIUM finding for 192.0.2.10 after five failed logins.'
            return
        }
        Start-Sleep -Seconds 10
    }
    throw 'No finding appeared within four minutes. Inspect EC2 system output and CloudWatch logs before retrying.'
} finally {
    Pop-Location
}
