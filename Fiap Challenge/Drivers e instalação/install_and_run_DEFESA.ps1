# install_and_run_VITORIA.ps1 - Versao Final da Vitoria (Corrigida)
# Foco: Limpeza Forense e Instalacao "na Marra", a prova de falhas.

# --- Configuracao ---
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DriverName = "RansomwareFilterDriver"
$ServiceName = "WatchdogService"
$DriverInfFile = Join-Path $PSScriptRoot "$DriverName.inf"
$ServiceFile = Join-Path $PSScriptRoot "WatchdogService.exe"
$DriverSysFile = "C:\Windows\System32\drivers\$DriverName.sys"
$DriverSysSource = Join-Path $PSScriptRoot "$DriverName.sys"

# --- Validacao de Administrador ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERRO: Este script deve ser executado como Administrador." -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    Exit
}

# --- Passo 1: Preparacao do Ambiente ---
Write-Host "Passo 1: Habilitando Test Signing..." -ForegroundColor Cyan
bcdedit.exe /set testsigning on
Write-Host "AVISO: Se esta for a primeira vez, REINICIE A VM para que o Test Signing seja ativado." -ForegroundColor Yellow

# --- Passo 2: Limpeza Forense (Agressiva, sem apagar .sys) ---
Write-Host "`nPasso 2: Limpando QUALQUER vestigio de instalacoes antigas..." -ForegroundColor Cyan
fltmc.exe unload $DriverName 2>$null
sc.exe delete $DriverName 2>$null
taskkill.exe /IM WatchdogService.exe /F 2>$null
sc.exe delete $ServiceName 2>$null
$ghostDrivers = pnputil /enum-drivers | Select-String -Pattern "$DriverName.inf" -Context 1,0 | ForEach-Object { ($_.Context.PreContext[0] -split ':')[1].Trim() }
if ($ghostDrivers) {
    foreach ($ghost in $ghostDrivers) {
        Write-Host "A remover driver fantasma encontrado: $ghost" -ForegroundColor Magenta
        pnputil /delete-driver $ghost /uninstall /force 2>$null
    }
}
# REMOVIDO: Remove-Item $DriverSysFile -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# --- Passo 3: Instalacao na Marra (O Jeito que Funciona) ---
Write-Host "`nPasso 3: Instalando os componentes..." -ForegroundColor Cyan

# Verifica se o .sys fonte existe antes de copiar
if (-not (Test-Path $DriverSysSource)) {
    Write-Host "ERRO: $DriverName.sys nao encontrado em $PSScriptRoot. Verifique o arquivo!" -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    Exit
}

Write-Host "A copiar o driver para a pasta do sistema..."
Copy-Item -Path $DriverSysSource -Destination $DriverSysFile -Force -ErrorAction Stop
if (-not (Test-Path $DriverSysFile)) {
    Write-Host "ERRO: Falha ao copiar $DriverName.sys para $DriverSysFile." -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    Exit
}

Write-Host "A instalar o pacote do driver (apenas para registro)..."
pnputil /add-driver "$DriverInfFile" /install

Write-Host "A criar o servico do driver manualmente (sc.exe)..."
sc.exe create $DriverName type= filesys start= demand binPath= $DriverSysFile group= "FSFilter Anti-Virus" depend= FltMgr displayname= "Filtro de Deteccao (FIAP)"

Write-Host "A forcar as chaves de registro da instancia (reg.exe)..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$DriverName\Instances" /v DefaultInstance /t REG_SZ /d "RansomwareFilterDriverInstance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$DriverName\Instances\RansomwareFilterDriverInstance" /v Altitude /t REG_SZ /d "328000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\$DriverName\Instances\RansomwareFilterDriverInstance" /v Flags /t REG_DWORD /d 0x0 /f

Write-Host "A criar o servico do Watchdog..."
sc.exe create $ServiceName type= own binPath= "`"$ServiceFile`""

# --- Passo 4: Execucao e Demonstracao ---
Write-Host "`nPasso 4: Iniciando os componentes..." -ForegroundColor Cyan
Write-Host "A carregar o driver $DriverName com fltmc..."
fltmc.exe load $DriverName

Write-Host "A verificar se o driver carregou..." -ForegroundColor Yellow
Start-Sleep -Seconds 1
$loadedFilter = fltmc.exe filters | findstr /i $DriverName
if (-not $loadedFilter) {
    Write-Host "ERRO FATAL: O driver foi instalado mas NAO CARREGOU. Verifique o Visualizador de Eventos." -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    Exit
}
Write-Host "SUCESSO! O driver esta carregado e ativo." -ForegroundColor Green
Write-Host "A iniciar o servico do Watchdog em uma nova janela..."
Start-Process -FilePath $ServiceFile -Verb RunAs  # Adicionei -Verb RunAs pra garantir Admin

Write-Host "----------------------------------------------------"
Write-Host "Sistema de Defesa ATIVO. A janela do Watchdog deve ter aparecido." -ForegroundColor Green
Write-Host "Para testar, abra o Bloco de Notas e guarde um ficheiro com extensao .encrypted. Observe a janela do Watchdog."
Read-Host "Pressione Enter para parar e limpar tudo."

# --- Passo 5: Limpeza Final ---
Write-Host "`nPasso 5: Parando e limpando tudo..." -ForegroundColor Cyan
taskkill.exe /IM WatchdogService.exe /F 2>$null
Start-Sleep -Seconds 1
fltmc.exe unload $DriverName 2>$null
sc.exe delete $DriverName 2>$null
sc.exe delete $ServiceName 2>$null
$finalGhost = pnputil /enum-drivers | Select-String -Pattern "$DriverName.inf" -Context 1,0 | ForEach-Object { ($_.Context.PreContext[0] -split ':')[1].Trim() }
if ($finalGhost) { pnputil /delete-driver $finalGhost /uninstall /force 2>$null }

Write-Host "`nDemonstracao concluida." -ForegroundColor Green
Read-Host "Pressione Enter para fechar."