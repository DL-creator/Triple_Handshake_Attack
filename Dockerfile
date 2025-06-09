# Build stage
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY . ./
RUN dotnet publish mitls.fsproj -c Release -o /out

# Runtime stage
FROM mcr.microsoft.com/dotnet/runtime:6.0
WORKDIR /app
COPY --from=build /out ./
COPY certs ./certs

ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8443 \
    SERVER_HOST=server \
    SERVER_PORT=4433

EXPOSE 8443

ENTRYPOINT ["dotnet", "mitls.dll"]
