# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copiar csproj e restaurar dependências
COPY *.sln .
COPY src/ComplianceMonitor.Domain/*.csproj ./src/ComplianceMonitor.Domain/
COPY src/ComplianceMonitor.Application/*.csproj ./src/ComplianceMonitor.Application/
COPY src/ComplianceMonitor.Infrastructure/*.csproj ./src/ComplianceMonitor.Infrastructure/
COPY src/ComplianceMonitor.Api/*.csproj ./src/ComplianceMonitor.Api/
COPY tests/ComplianceMonitor.UnitTests/*.csproj ./tests/ComplianceMonitor.UnitTests/
COPY tests/ComplianceMonitor.IntegrationTests/*.csproj ./tests/ComplianceMonitor.IntegrationTests/
COPY tests/ComplianceMonitor.FunctionalTests/*.csproj ./tests/ComplianceMonitor.FunctionalTests/

RUN dotnet restore

# Copiar todo o código fonte
COPY . .

# Publicar a aplicação
RUN dotnet publish -c Release -o out src/ComplianceMonitor.Api/ComplianceMonitor.Api.csproj

# Runtime Stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime

# Instalar curl, unzip e outras dependências
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl \
       ca-certificates \
       unzip \
       apt-transport-https \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalar Trivy para escaneamento de vulnerabilidades
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy --version

WORKDIR /app
COPY --from=build /app/out ./

# Criar usuário não-root e configurar permissões
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app

# Configurar volumes para persistência de dados
VOLUME /app/data

# Configurar variáveis de ambiente
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

# Expor a porta
EXPOSE 8080

# Mudar para usuário não-root
USER appuser

# Verificação de saúde
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Comando para iniciar a aplicação
ENTRYPOINT ["dotnet", "ComplianceMonitor.Api.dll"]