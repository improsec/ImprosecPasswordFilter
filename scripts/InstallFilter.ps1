function Test-RegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Path,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Key
    )

    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Key -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

$path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$name = "Notification Packages"
$filt = "ipfilter"

New-Item -Path "C:\" -Name "improsec" -ItemType Directory -Force | Out-Null
Set-Content -Path "C:\improsec\enabled.txt" -Value "1" -Force | Out-Null

Copy-Item -Path "$PSScriptRoot\blacklist.txt" -Destination "C:\improsec\blacklist.txt" -Force
Copy-Item -Path "$PSScriptRoot\$filt.dll" -Destination "C:\Windows\System32\$filt.dll" -Force

if (Test-RegistryValue -Path $path -Key $name) {
    $values = @((Get-ItemPropertyValue -Path $path -Name $name))

    if (!$values.Contains($filt)) {
        $values += $filt
    }

    Set-ItemProperty -Path $path -Name $name -Value $values
} else {
    New-ItemProperty -Path $path -Name $name -Value @($filt) -PropertyType MultiString
}