# Install NuGet package provider
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Write-Host "[*] Installing required package provider."

# Install ADCSTemplate
Write-Host "[*] Installing ADCSTemplate module." 
Install-Module ADCSTemplate -Force

# Import the ADCSTemplate module if not already loaded
if (-not (Get-Module -Name ADCSTemplate -ErrorAction SilentlyContinue)) {
    Import-Module ADCSTemplate
}
Write-Host "[*] Required module installed and imported." 

# Create temporary new directory
cd \
md ADCS
cd ADCS
Write-Host "[*] Temporary directory created."

# Download .json template files from GitHub repo
# Define the filenames to download

$fileNames = @(
    "Vuln-ESC1.json",
    "Vuln-ESC2.json",
    "Vuln-ESC3-1.json",
    "Vuln-ESC3-2.json",
    "Vuln-ESC4.json"
)

$baseURL = "https://raw.githubusercontent.com/arth0sz/Practice-AD-CS-Domain-Escalation/main/Vulnerable-Templates/"

# Loop through each filename and download the corresponding file
foreach ($fileName in $fileNames) {
    $url = $baseURL + $fileName
    Invoke-WebRequest -URI $url -OutFile $fileName
}

Write-Host "[*] Vulnerable template files downloaded."

$folderPath = Get-Location
$templates = Get-ChildItem -Path $folderPath -File

foreach ($template in $templates) {
    # Get the template names from the files
    $templateName = $template.BaseName
	#Import and publish templates
    New-ADCSTemplate -DisplayName $templateName -JSON (Get-Content .\$templateName.json -Raw) -Publish
	# Issue templates
    Set-ADCSTemplateACL -DisplayName $templateName -Identity 'certipied\domain users' -Enroll -AutoEnroll

}

Write-Host "[*] Vulnerable templates published and issued."

# Download self-signed ssl certificate template files from GitHub repo
# separation needed to ensure it's not vulnerable
Invoke-WebRequest -URI "https://raw.githubusercontent.com/arth0sz/Practice-AD-CS-Domain-Escalation/main/Vulnerable-Templates/IP-ssl.json" -OutFile .\IP-ssl.json
New-ADCSTemplate -DisplayName IP-ssl -JSON (Get-Content .\IP-ssl.json -Raw) -Publish
Set-ADCSTemplateACL -DisplayName IP-ssl -Identity 'certipied\domain admins' -Enroll -AutoEnroll

cd \
Remove-Item -Path ADCS -Recurse

Write-Host "[*] Temporary directory removed."