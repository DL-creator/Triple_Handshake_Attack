# Use the .NET SDK image for Linux
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build

WORKDIR /app

# Copy project files
COPY . ./
# Build the project
RUN dotnet build mitls.fsproj -c Release

# Runtime image for running the binary
FROM mcr.microsoft.com/dotnet/runtime:6.0

WORKDIR /app
COPY --from=build /app/bin/Release/net6.0/ . 

# Default MITM settings baked in
ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8443 \
    SERVER_HOST=server \
    SERVER_PORT=4433

# Expose the MITM listening port
EXPOSE 8443


# Set default command
ENTRYPOINT ["dotnet", "Program.dll"]
