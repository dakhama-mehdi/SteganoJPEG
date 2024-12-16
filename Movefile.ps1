
$sourceDir = "C:\Users\user1\Desktop\Shavi"  # Dossier source sur le SSD
$externalDriveDir = "C:\Temp1"  # Dossier destination sur le disque dur externe


$daysThreshold = 5
$cutoffDate = (Get-Date).AddDays(-$daysThreshold)

# Obtenir les fichiers du dossier source
$files = Get-ChildItem -Path $sourceDir -File

# Filtrer les fichiers plus anciens que 5 jours
$oldFiles = $files | Where-Object { $_.LastWriteTime -lt $cutoffDate }

# Déplacer les fichiers plus anciens sur le disque dur externe
foreach ($file in $oldFiles) {
    $destinationPath = Join-Path -Path $externalDriveDir -ChildPath $file.Name
    Move-Item -Path $file.FullName -Destination $destinationPath -Force
    Write-Output "Déplacement du fichier '$($file.Name)' vers '$destinationPath' $(Get-Date) " | Out-File C:\Temp1\text.csv -Append
}

# Optionnel : Afficher un message si aucun fichier n'est trouvé pour être déplacé
if ($oldFiles.Count -eq 0) {
    Write-Host "Aucun fichier plus ancien que $daysThreshold jours trouvé à déplacer."
}
