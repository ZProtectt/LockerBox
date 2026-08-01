# quick_push.ps1
Write-Host "--- Automatisation du commit/push ---"
git add .
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
git commit -m "Mise à jour automatique : $date"
git push origin main
Write-Host "--- Push effectué avec succès ---"