param(
    [string]$OpenShiftApiUrl,
    [string]$Username,
    [string]$Password,
    [string]$KubeconfigPath = "$HOME\.kube\config"
)

Write-Host "Configurando ambiente de desenvolvimento para OpenShift..." -ForegroundColor Green

# Verificar se OC CLI está instalado
if (-not (Get-Command oc -ErrorAction SilentlyContinue)) {
    Write-Host "OC CLI não encontrado. Por favor, instale a ferramenta de linha de comando do OpenShift." -ForegroundColor Red
    exit 1
}

# Login no OpenShift
Write-Host "Fazendo login no OpenShift..." -ForegroundColor Cyan
oc login -u $Username -p $Password $OpenShiftApiUrl

if ($LASTEXITCODE -ne 0) {
    Write-Host "Falha ao fazer login no OpenShift. Verifique suas credenciais." -ForegroundColor Red
    exit 1
}

# Obter token
$token = oc whoami -t
Write-Host "Token obtido com sucesso!" -ForegroundColor Green

# Exportar token para variável de ambiente
[Environment]::SetEnvironmentVariable("OPENSHIFT_TOKEN", $token, "User")
Write-Host "Token configurado como variável de ambiente OPENSHIFT_TOKEN" -ForegroundColor Green

# Exportar kubeconfig
Write-Host "Exportando kubeconfig para: $KubeconfigPath" -ForegroundColor Cyan
oc config view --raw > $KubeconfigPath

# Atualizar appsettings.Development.json
$appSettingsPath = "src\ComplianceMonitor.Api\appsettings.Development.json"
if (Test-Path $appSettingsPath) {
    Write-Host "Atualizando $appSettingsPath com as configurações do OpenShift..." -ForegroundColor Cyan
    
    $appSettings = Get-Content $appSettingsPath -Raw | ConvertFrom-Json
    
    # Criar a estrutura se não existir
    if (-not $appSettings.Kubernetes) {
        $appSettings | Add-Member -MemberType NoteProperty -Name "Kubernetes" -Value @{}
    }
    
    # Atualizar as configurações
    $appSettings.Kubernetes.ApiUrl = $OpenShiftApiUrl
    $appSettings.Kubernetes.Token = $token
    $appSettings.Kubernetes.KubeconfigPath = $KubeconfigPath
    $appSettings.Kubernetes.VerifySsl = $false
    
    # Adicionar configurações do Trivy se não existirem
    if (-not $appSettings.Trivy) {
        $appSettings | Add-Member -MemberType NoteProperty -Name "Trivy" -Value @{}
    }
    
    # Configurações do Trivy para o OpenShift
    $appSettings.Trivy.UseOpenShiftCredentials = $true
    
    # Determinar o URL do registro interno
    $registryUrl = "image-registry.openshift-image-registry.svc:5000"
    try {
        $route = oc get route -n openshift-image-registry default-route -o jsonpath='{.spec.host}' -o 2>$null
        if ($route) {
            $registryUrl = $route
        }
    } catch {
        Write-Host "Não foi possível determinar o URL do registro interno, usando padrão: $registryUrl" -ForegroundColor Yellow
    }
    
    $appSettings.Trivy.OpenShiftRegistry = $registryUrl
    
    # Salvar o arquivo
    $appSettings | ConvertTo-Json -Depth 10 | Set-Content $appSettingsPath
    
    Write-Host "Arquivo appsettings.Development.json atualizado com sucesso!" -ForegroundColor Green
} else {
    Write-Host "Arquivo appsettings.Development.json não encontrado em: $appSettingsPath" -ForegroundColor Red
}

Write-Host "`nAmbiente configurado com sucesso para desenvolvimento com OpenShift!" -ForegroundColor Green
Write-Host "Execute o projeto localmente com: dotnet run --project src\ComplianceMonitor.Api\ComplianceMonitor.Api.csproj" -ForegroundColor Cyan