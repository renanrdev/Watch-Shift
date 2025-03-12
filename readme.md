# Compliance Monitor

Uma aplicação .NET 8 para monitoramento de conformidade e segurança em clusters Kubernetes e OpenShift.

## Visão Geral

O Compliance Monitor é uma solução completa para monitoramento de conformidade e segurança em ambientes Kubernetes e OpenShift. Ele oferece recursos para:

- Varredura de vulnerabilidades em imagens de contêiner usando Trivy
- Verificação de políticas de segurança em recursos do Kubernetes/OpenShift
- Monitoramento de regras de RBAC (controle de acesso)
- Verificação de SCC (Security Context Constraints) no OpenShift
- Monitoramento de políticas de rede

## Arquitetura

A aplicação segue os princípios de Arquitetura Limpa (Clean Architecture):

- **Domain Layer**: Contém entidades, regras de negócio e interfaces do domínio.
- **Application Layer**: Implementa casos de uso e orquestra entidades de domínio.
- **Infrastructure Layer**: Fornece implementações concretas das interfaces de domínio.
- **API Layer**: Expõe a funcionalidade da aplicação por meio de RESTful API.

### Tecnologias Utilizadas

- .NET 8
- Entity Framework Core
- AutoMapper
- Kubernetes Client para .NET
- Trivy (para varredura de vulnerabilidades)
- Swagger
- xUnit (para testes)

## Principais Recursos

### Políticas de Conformidade

O sistema permite a configuração de políticas de conformidade que verificam vários aspectos da segurança do Kubernetes:

- **Políticas RBAC**: Verificam permissões de controle de acesso
- **Políticas SCC**: Verificam restrições de contexto de segurança no OpenShift
- **Políticas de Rede**: Verificam a configuração da rede do cluster

### Varredura de Vulnerabilidades

- Varredura sob demanda de imagens específicas
- Varredura automática de todas as imagens em execução no cluster
- Relatórios de vulnerabilidades detalhados

### Dashboard e Alertas

- Dashboard com métricas consolidadas
- Alertas para problemas de conformidade
- Relatórios por namespace

## Começando

### Pré-requisitos

- .NET 8 SDK
- SQL Server ou SQL Server Express
- Kubernetes ou OpenShift (local ou remoto)
- Trivy instalado (para varredura de vulnerabilidades)

### Instalação

1. Clone o repositório
   ```bash
   git clone https://github.com/sua-organizacao/compliance-monitor.git
   cd compliance-monitor
   ```

2. Configure as conexões no arquivo appsettings.json
   ```json
   {
       "ConnectionStrings": {
           "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=ComplianceMonitorDb;Trusted_Connection=True;"
       },
       "Kubernetes": {
           "KubeconfigPath": "~/.kube/config"
       }
   }
   ```

3. Execute as migrações do banco de dados
   ```bash
   dotnet ef database update --project src/ComplianceMonitor.Infrastructure --startup-project src/ComplianceMonitor.Api
   ```

4. Execute a aplicação
   ```bash
   dotnet run --project src/ComplianceMonitor.Api
   ```

5. Acesse o Swagger UI
   ```
   https://localhost:5001/swagger
   ```

## Estrutura da Solução

```
ComplianceMonitor.sln
├── src/
│   ├── ComplianceMonitor.Domain/               # Camada de domínio
│   ├── ComplianceMonitor.Application/          # Camada de aplicação
│   ├── ComplianceMonitor.Infrastructure/       # Camada de infraestrutura
│   └── ComplianceMonitor.Api/                  # API
└── tests/                                      # Testes
    ├── ComplianceMonitor.UnitTests/
    ├── ComplianceMonitor.IntegrationTests/
    └── ComplianceMonitor.FunctionalTests/
```

## Políticas Pré-configuradas

O sistema inclui várias políticas pré-configuradas:

- **RBAC**
  - Proibir permissões cluster-admin para contas não confiáveis
  - Evitar permissões wildcard para recursos e verbos
  - Controlar verbos sensíveis para recursos críticos

- **SCC (OpenShift)**
  - Proibir contêineres privilegiados
  - Proibir capabilities perigosas
  - Restringir caminhos para montagem

- **Políticas de Rede**
  - Garantir políticas de default deny
  - Isolar adequadamente namespaces
  - Restringir portas sensíveis
