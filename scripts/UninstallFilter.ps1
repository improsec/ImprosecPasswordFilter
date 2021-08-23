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
$filt = "ipf"

Set-Content -Path "C:\improsec-filter\weak-enabled.txt" -Value "0" -Force | Out-Null
Set-Content -Path "C:\improsec-filter\leaked-enabled.txt" -Value "0" -Force | Out-Null

if (Test-RegistryValue -Path $path -Key $name) {
    $oldval = @((Get-ItemPropertyValue -Path $path -Name $name))
    $newval = @()

    foreach ($v in $oldval) {
        if ($v -ne $filt) {
            $newval += $v
        }
    }

    Set-ItemProperty -Path $path -Name $name -Value $newval
}
