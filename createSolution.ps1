# Define o nome da solução
$solutionName = "ComplianceMonitor"
$basePath = (Get-Location).Path

# Limpar qualquer solução existente e recriá-la
Remove-Item -Path "$solutionName.sln" -ErrorAction SilentlyContinue
dotnet new sln -n $solutionName

# Criar pastas principais se elas não existirem
New-Item -Path "src" -ItemType Directory -Force | Out-Null
New-Item -Path "tests" -ItemType Directory -Force | Out-Null

# Remover projetos existentes se necessário
Remove-Item -Path "src\$solutionName.Domain" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "src\$solutionName.Application" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "src\$solutionName.Infrastructure" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "src\$solutionName.Api" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "tests\$solutionName.UnitTests" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "tests\$solutionName.IntegrationTests" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "tests\$solutionName.FunctionalTests" -Recurse -ErrorAction SilentlyContinue

# Criar projetos da camada src
Write-Host "Criando projetos src..."
dotnet new classlib -n "$solutionName.Domain" -o "src\$solutionName.Domain" -f net8.0
dotnet new classlib -n "$solutionName.Application" -o "src\$solutionName.Application" -f net8.0
dotnet new classlib -n "$solutionName.Infrastructure" -o "src\$solutionName.Infrastructure" -f net8.0
dotnet new webapi -n "$solutionName.Api" -o "src\$solutionName.Api" -f net8.0

# Criar projetos de teste
Write-Host "Criando projetos tests..."
dotnet new xunit -n "$solutionName.UnitTests" -o "tests\$solutionName.UnitTests" -f net8.0
dotnet new xunit -n "$solutionName.IntegrationTests" -o "tests\$solutionName.IntegrationTests" -f net8.0
dotnet new xunit -n "$solutionName.FunctionalTests" -o "tests\$solutionName.FunctionalTests" -f net8.0

# Adicionar projetos à solução explicitamente
Write-Host "Adicionando projetos à solução..."
dotnet sln add "src\$solutionName.Domain\$solutionName.Domain.csproj"
dotnet sln add "src\$solutionName.Application\$solutionName.Application.csproj"
dotnet sln add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj"
dotnet sln add "src\$solutionName.Api\$solutionName.Api.csproj"
dotnet sln add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj"
dotnet sln add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj"
dotnet sln add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj"

# Criar estrutura de referências
Write-Host "Configurando referências entre projetos..."
# Application depende de Domain
dotnet add "src\$solutionName.Application\$solutionName.Application.csproj" reference "src\$solutionName.Domain\$solutionName.Domain.csproj"

# Infrastructure depende de Application e Domain
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" reference "src\$solutionName.Domain\$solutionName.Domain.csproj"
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" reference "src\$solutionName.Application\$solutionName.Application.csproj"

# API depende de Application, Domain e Infrastructure
dotnet add "src\$solutionName.Api\$solutionName.Api.csproj" reference "src\$solutionName.Domain\$solutionName.Domain.csproj"
dotnet add "src\$solutionName.Api\$solutionName.Api.csproj" reference "src\$solutionName.Application\$solutionName.Application.csproj"
dotnet add "src\$solutionName.Api\$solutionName.Api.csproj" reference "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj"

# Adicionar referências aos projetos de testes
dotnet add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj" reference "src\$solutionName.Domain\$solutionName.Domain.csproj"
dotnet add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj" reference "src\$solutionName.Application\$solutionName.Application.csproj"

dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" reference "src\$solutionName.Domain\$solutionName.Domain.csproj"
dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" reference "src\$solutionName.Application\$solutionName.Application.csproj"
dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" reference "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj"

dotnet add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj" reference "src\$solutionName.Api\$solutionName.Api.csproj"

# Adicionar pacotes NuGet comuns para cada projeto
Write-Host "Instalando pacotes NuGet..."

# Pacotes para Application
dotnet add "src\$solutionName.Application\$solutionName.Application.csproj" package AutoMapper -v 12.0.1
dotnet add "src\$solutionName.Application\$solutionName.Application.csproj" package AutoMapper.Extensions.Microsoft.DependencyInjection -v 12.0.1
dotnet add "src\$solutionName.Application\$solutionName.Application.csproj" package FluentValidation -v 11.8.0
dotnet add "src\$solutionName.Application\$solutionName.Application.csproj" package FluentValidation.DependencyInjectionExtensions -v 11.8.0
dotnet add "src\$solutionName.Application\$solutionName.Application.csproj" package Microsoft.Extensions.Logging.Abstractions -v 8.0.0

# Pacotes para Infrastructure
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" package Microsoft.EntityFrameworkCore -v 8.0.0
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" package Microsoft.EntityFrameworkCore.SqlServer -v 8.0.0
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" package Microsoft.EntityFrameworkCore.Tools -v 8.0.0
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" package Microsoft.Extensions.Http -v 8.0.0
dotnet add "src\$solutionName.Infrastructure\$solutionName.Infrastructure.csproj" package KubernetesClient -v 12.1.1

# Pacotes para API
dotnet add "src\$solutionName.Api\$solutionName.Api.csproj" package Swashbuckle.AspNetCore -v 6.5.0
dotnet add "src\$solutionName.Api\$solutionName.Api.csproj" package Microsoft.AspNetCore.OpenApi -v 8.0.0
dotnet add "src\$solutionName.Api\$solutionName.Api.csproj" package Microsoft.EntityFrameworkCore.Design -v 8.0.0

# Pacotes para testes
dotnet add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj" package Microsoft.NET.Test.Sdk -v 17.8.0
dotnet add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj" package Moq -v 4.20.69
dotnet add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj" package xunit -v 2.6.1
dotnet add "tests\$solutionName.UnitTests\$solutionName.UnitTests.csproj" package xunit.runner.visualstudio -v 2.5.3

dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" package Microsoft.NET.Test.Sdk -v 17.8.0
dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" package Microsoft.AspNetCore.Mvc.Testing -v 8.0.0
dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" package xunit -v 2.6.1
dotnet add "tests\$solutionName.IntegrationTests\$solutionName.IntegrationTests.csproj" package xunit.runner.visualstudio -v 2.5.3

dotnet add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj" package Microsoft.NET.Test.Sdk -v 17.8.0
dotnet add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj" package Microsoft.AspNetCore.Mvc.Testing -v 8.0.0
dotnet add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj" package xunit -v 2.6.1
dotnet add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj" package xunit.runner.visualstudio -v 2.5.3
dotnet add "tests\$solutionName.FunctionalTests\$solutionName.FunctionalTests.csproj" package Testcontainers -v 3.5.0

# Criar estrutura padrão de pastas em cada projeto
Write-Host "Criando estrutura de pastas..."

$projectFolders = @{
    "Domain" = @("Entities", "Enums", "Interfaces", "Specifications", "Exceptions")
    "Application" = @("DTOs", "Interfaces", "Mapping", "Services", "Common")
    "Infrastructure" = @("Data", "Kubernetes", "Scanners", "Background", "Extensions")
    "Api" = @("Controllers", "Middleware", "Extensions")
}

foreach ($project in $projectFolders.Keys) {
    foreach ($folder in $projectFolders[$project]) {
        New-Item -Path "src\$solutionName.$project\$folder" -ItemType Directory -Force | Out-Null
    }
}

# Criar pastas específicas para testes
$testFolders = @{
    "UnitTests" = @("Domain", "Application")
    "IntegrationTests" = @("Api", "Infrastructure")
    "FunctionalTests" = @("Scenarios", "Helpers")
}

foreach ($project in $testFolders.Keys) {
    foreach ($folder in $testFolders[$project]) {
        New-Item -Path "tests\$solutionName.$project\$folder" -ItemType Directory -Force | Out-Null
    }
}

# Garantir que o arquivo de solução está atualizado
dotnet sln list

Write-Host "Processo concluído. Por favor, siga estas etapas:"
Write-Host "1. Feche o Visual Studio se estiver aberto"
Write-Host "2. Abra novamente a solução $solutionName.sln"
Write-Host "3. Todos os projetos devem estar visíveis no Solution Explorer"