(*
 * Copyright 2015 INRIA and Microsoft Corporation
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

#light "off"

(* Handshake protocol messages *)
module HandshakeMessages

open Bytes
open CoreKeys
open Error
open TLSError
open TLSConstants
open TLSExtensions
open TLSInfo
open Range

(*** Following RFC5246 A.4 *)

type PreHandshakeType =
    | HT_hello_request
    | HT_client_hello
    | HT_server_hello
    | HT_certificate
    | HT_server_key_exchange
    | HT_certificate_request
    | HT_server_hello_done
    | HT_certificate_verify
    | HT_client_key_exchange
    | HT_finished

type HandshakeType = PreHandshakeType

let htBytes t =
    match t with
    | HT_hello_request       -> abyte   0uy
    | HT_client_hello        -> abyte   1uy
    | HT_server_hello        -> abyte   2uy
    | HT_certificate         -> abyte  11uy
    | HT_server_key_exchange -> abyte  12uy
    | HT_certificate_request -> abyte  13uy
    | HT_server_hello_done   -> abyte  14uy
    | HT_certificate_verify  -> abyte  15uy
    | HT_client_key_exchange -> abyte  16uy
    | HT_finished            -> abyte  20uy

let parseHt (b:bytes) =
    match cbyte b with
    |   0uy  -> correct(HT_hello_request      )
    |   1uy  -> correct(HT_client_hello       )
    |   2uy  -> correct(HT_server_hello       )
    |  11uy  -> correct(HT_certificate        )
    |  12uy  -> correct(HT_server_key_exchange)
    |  13uy  -> correct(HT_certificate_request)
    |  14uy  -> correct(HT_server_hello_done  )
    |  15uy  -> correct(HT_certificate_verify )
    |  16uy  -> correct(HT_client_key_exchange)
    |  20uy  -> correct(HT_finished           )
    | _   -> let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_decode_error, reason)

/// Handshake message format

let messageBytes ht data =
    let htb = htBytes ht in
    let vldata = vlbytes 3 data in
    htb @| vldata

let parseMessage buf =
    (* Somewhat inefficient implementation:
       we repeatedly parse the first 4 bytes of the incoming buffer until we have a complete message;
       we then remove that message from the incoming buffer. *)
    if length buf < 4 then Correct(None) (* not enough data to start parsing *)
    else
        let (hstypeb,rem) = Bytes.split buf 1 in
        match parseHt hstypeb with
        | Error z ->  Error z
        | Correct(hstype) ->
            match vlsplit 3 rem with
            | Error z -> Correct(None) // not enough payload, try next time
            | Correct(res) ->
                let (payload,rem) = res in
                let to_log = messageBytes hstype payload in
                let res = (rem,hstype,payload,to_log) in
                let res = Some(res) in
                correct(res)

// We implement locally fragmentation, not hiding any length
#if verify
type unsafe = Unsafe of epoch
#endif
let makeFragment ki b =
    let i = mk_id ki in
    if length b < fragmentLength then
      let r0 = (length b, length b) in
      let f = HSFragment.fragmentPlain i r0 b in
      (r0,f,empty_bytes)
    else
      let (b0,rem) = Bytes.split b fragmentLength in
      let r0 = (length b0, length b0) in
      let f = HSFragment.fragmentPlain i r0 b0 in
      (r0,f,rem)

// we could use something more general for parsing lists, e.g.
// let rec parseList parseOne b =
//     if length b = 0 then correct([])
//     else
//     match parseOne b with
//     | Correct(x,b) ->
//         match parseList parseOne b with
//         | Correct(xs) -> correct(x::xs)
//         | Error z -> Error z
//     | Error z -> Error z

(** General message parsing *)
let splitMessage ht data =
  if length data >= 1 then
    let (ht', pl) = split data 1 in
        if htBytes ht = ht' then
            Correct pl
        else
            Error (AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
  else
    Error (AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(** A.4.1 Hello Messages *)

#if verify
type log = bytes         (* message payloads so far, to be eventually authenticated *)
type cVerifyData = bytes (* ClientFinished payload *)
type sVerifyData = bytes (* ServerFinished payload *)
#endif

type chello = | ClientHelloMsg of (bytes * ProtocolVersion * random * sessionID * cipherSuites * list<Compression> * bytes)

#if verify
type preds =
    | ServerLogBeforeClientCertificateVerifyRSA of SessionInfo * bytes
    | ServerLogBeforeClientCertificateVerify of SessionInfo * bytes
    | ServerLogBeforeClientCertificateVerifyDHE of SessionInfo * bytes
    | ServerLogBeforeClientFinished of SessionInfo * bytes
    | UpdatesClientAuth of SessionInfo * SessionInfo
    | ClientLogBeforeClientFinishedRSA_NoAuth of SessionInfo * log
    | UpdatesPmsClientID of SessionInfo * SessionInfo
    | ClientLogBeforeCertificateVerifyRSA_Auth of SessionInfo * log
    | ClientLogBeforeClientFinishedRSA_TryNoAuth of SessionInfo * log
    | ClientLogBeforeClientFinishedRSA_Auth of SessionInfo * log
    | ClientLogBeforeCertificateVerifyDHE_Auth of SessionInfo * log
    | ClientLogBeforeClientFinishedDHE_Auth of SessionInfo * log
    | ClientLogBeforeClientFinishedDHE_TryNoAuth of SessionInfo * log
    | ClientLogBeforeClientFinishedDHE_NoAuth of SessionInfo * log
    | UpdatesServerSigAlg of SessionInfo * SessionInfo
    | ClientLogBeforeServerHelloDoneRSA_NoAuth of SessionInfo * log
    | ClientLogAfterServerHelloDoneRSA of SessionInfo * log
    | ClientLogBeforeServerHelloDoneDHE_NoAuth of SessionInfo * log
    | ClientLogAfterServerHelloDoneDHE of SessionInfo * log
    | UpdatesPmsID of SessionInfo * SessionInfo
    | UpdatesClientID of SessionInfo * SessionInfo
    | UpdatesServerID of SessionInfo * SessionInfo
    | ServerLogBeforeClientFinished_NoAuth of SessionInfo * log
    | ServerLogBeforeClientCertificateDHE_NoAuth of SessionInfo * log
    | ServerLogBeforeClientFinished_Auth of SessionInfo * log
    | UpdatesClientSigAlg of SessionInfo * SessionInfo
    | ServerLogBeforeClientCertificateRSA_NoAuth of SessionInfo * ProtocolVersion * log
    | ServerLogBeforeClientCertificateDHE_Auth of SessionInfo * log
    | ServerLogBeforeServerFinishedResume of abbrInfo * SessionInfo * log
    | ServerLogBeforeServerFinished of SessionInfo * log
    | ServerLogBeforeClientKeyExchangeRSA_Auth of SessionInfo * ProtocolVersion * log
    | ServerLogBeforeClientKeyExchangeDHE_Auth of SessionInfo * log
#endif

#if verify
let popBytes i data =
    if length data >= i then
        let (data, r) = split data i in
            Correct (data, r)
    else
        Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let popVLBytes i data =
    if length data >= i then
        match vlsplit i data with
        | Error z -> Error z
        | Correct data -> let (data, r) = data in Correct (data, r)
    else
        Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let popProtocolVersion data =
    match popBytes 2 data with
    | Error z -> Error z
    | Correct data ->
        let (pv, r) = data in
            match parseVersion pv with
            | Error z -> Error z
            | Correct pv -> Correct (pv, r)

let popClientRandom data = popBytes   32 data
let popCSBytes      data = popVLBytes  2 data
let popCPBytes      data = popVLBytes  1 data

let popSid data =
    match popVLBytes 1 data with
    | Error z -> Error z
    | Correct data ->
        let (sid, data) = data in
            if length sid <= 32 then
                Correct (sid, data)
            else
                Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let popCS data =
    let d = popCSBytes data in
    match d with
    | Error z -> Error z
    | Correct data ->
        let (csb, r) = data in
            match parseCipherSuites csb with
            | Error z -> Error z
            | Correct cs -> let aout = (cs, r) in correct aout

let popCP data =
    let d = popCPBytes data in
    match d with
    | Error z -> Error z
    | Correct data ->
        let (cpb, r) = data in
        let cp = parseCompressions cpb in
            correct (cp, r)

let parseClientHelloDumb data =
    (* Protocol version *)
    match popProtocolVersion data with
    | Error z -> Error z
    | Correct data ->
    let (pv, data) = data in

    (* SessionID *)
    match popClientRandom data with
    | Error z -> Error z
    | Correct data ->
    let (cr, data) = data in

    (* Client random *)
    match popSid data with
    | Error z -> Error z
    | Correct data ->
    let (sid, data) = data in

    (* CipherSuites *)
    match popCS data with
    | Error z -> Error z
    | Correct data ->
    let (cs, data) = data in

    (* Compression *)
    match popCP data with
    | Error z -> Error z
    | Correct data ->
    let (cp, data) = data in

        Correct (pv,cr,sid,cs,cp,data)
#endif

let parseClientHello data =
    if length data >= 34 then
        let (clVerBytes,cr,data) = split2 data 2 32 in
        match parseVersion clVerBytes with
        | Error z -> Error z
        | Correct(cv) ->
        if length data >= 1 then
            match vlsplit 1 data with
            | Error z -> Error z
            | Correct (res) ->
            let (sid,data) = res in
            if length sid <= 32 then
                if length data >= 2 then
                    match vlsplit 2 data with
                    | Error z -> Error z
                    | Correct (res) ->
                    let (clCiphsuitesBytes,data) = res in
                    match parseCipherSuites clCiphsuitesBytes with
                    | Error(z) -> Error(z)
                    | Correct (clientCipherSuites) ->
                    if length data >= 1 then
                        match vlsplit 1 data with
                        | Error(z) -> Error(z)
                        | Correct (res) ->
                        let (cmBytes,extensions) = res in
                        let cm = parseCompressions cmBytes in
                        correct(cv,cr,sid,clientCipherSuites,cm,extensions)
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let clientHelloBytes poptions crand session ext =
    let mv = poptions.maxVer in
    let cVerB      = versionBytes mv in
    let random     = crand in
    let csessB     = vlbytes 1 session in
    let cs = poptions.ciphersuites in
    let csb = cipherSuitesBytes cs in
    let ccsuitesB  = vlbytes 2 csb in
    let cm = poptions.compressions in
    let cmb = compressionMethodsBytes cm in
    let ccompmethB = vlbytes 1 cmb in
    let data = cVerB @| (random @| (csessB @| (ccsuitesB @| (ccompmethB @| ext)))) in
    messageBytes HT_client_hello data

/// flex variant of clientHelloBytes (could be merged)
let clientHelloBytes2 pv css comps crand session ext =
    let cVerB      = versionBytes pv in
    let random     = crand in
    let csessB     = vlbytes 1 session in
    let csb = cipherSuitesBytes css in
    let ccsuitesB  = vlbytes 2 csb in
    let cmb = compressionMethodsBytes comps in
    let ccompmethB = vlbytes 1 cmb in
    let data = cVerB @| (random @| (csessB @| (ccsuitesB @| (ccompmethB @| ext)))) in
    messageBytes HT_client_hello data

let serverHelloBytes sinfo srand ext =
    let verB = versionBytes sinfo.protocol_version in
    let sidB = vlbytes 1 sinfo.sessionID in
    let csB = cipherSuiteBytes sinfo.cipher_suite in
    let cmB = compressionBytes sinfo.compression in
    let data = verB @| srand @| sidB @| csB @| cmB @| ext in
    messageBytes HT_server_hello data

let parseServerHello data =
    if length data >= 34 then
        let (serverVerBytes,serverRandomBytes,data) = split2 data 2 32 in
        match parseVersion serverVerBytes with
        | Error z -> Error z
        | Correct(serverVer) ->
            if length data >= 1 then
                match vlsplit 1 data with
                | Error z -> Error z
                | Correct (res) ->
                    let (sid,data) = res in
                    if length sid <= 32 then
                        if length data >= 3 then
                            let (csBytes,cmBytes,data) = split2 data 2 1 in
                            match parseCipherSuite csBytes with
                            | Error(z) -> Error(z)
                            | Correct(cs) ->
                                (match parseCompression cmBytes with
                                | Error(z) -> Error(z)
                                | Correct(cm) ->
                                correct(serverVer,serverRandomBytes,sid,cs,cm,data))
                        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let helloRequestBytes = messageBytes HT_hello_request empty_bytes

let CCSBytes = abyte 1uy

(** A.4.2 Server Authentication and Key Exchange Messages *)

let serverHelloDoneBytes = messageBytes HT_server_hello_done empty_bytes

let serverCertificateBytes cl = messageBytes HT_certificate (Cert.certificateListBytes cl)

let clientCertificateBytes (cs:option<(Cert.chain * Sig.alg * Sig.skey)>) =

    match cs with
    | None -> let clb = Cert.certificateListBytes [] in messageBytes HT_certificate clb
    | Some(v) ->
        let (certList,_,_) = v in
        let clb = Cert.certificateListBytes certList in
        messageBytes HT_certificate clb

let parseClientOrServerCertificate data =
    if length data >= 3 then
        match vlparse 3 data with
        | Error z -> let (x,y) = z in Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ y)
        | Correct (certList) -> Cert.parseCertificateList certList
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let sigHashAlgBytesVersion version cs =
     match version with
#if tls13
        | TLS_1p3
#endif
        | TLS_1p2 ->
            let defaults = default_sigHashAlg version cs in
            let res = sigHashAlgListBytes defaults in
            vlbytes 2 res
        | TLS_1p1 | TLS_1p0 | SSL_3p0 -> empty_bytes

let parseSigHashAlgVersion version data =
    match version with
#if tls13
    | TLS_1p3
#endif
    | TLS_1p2->
        if length data >= 2 then
            match vlsplit 2 data with
            | Error(z) -> Error(z)
            | Correct (res) ->
            let (sigAlgsBytes,data) = res in
            match parseSigHashAlgList sigAlgsBytes with
            | Error(z) -> Error(z)
            | Correct (sigAlgsList) -> correct (sigAlgsList,data)
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | TLS_1p1 | TLS_1p0 | SSL_3p0 ->
        correct ([],data)

let certificateRequestBytes sign cs version =
    let certTypes = defaultCertTypes sign cs in
    let ctb = certificateTypeListBytes certTypes in
    let ctb = vlbytes 1 ctb in
    let sigAndAlg = sigHashAlgBytesVersion version cs in
    (* We specify no cert auth *)
    let distNames = distinguishedNameListBytes [] in
    let distNames = vlbytes 2 distNames in
    let data = ctb
            @| sigAndAlg
            @| distNames in
    messageBytes HT_certificate_request data

let parseCertificateRequest version data: Result<(list<certType> * list<Sig.alg> * list<string>)> =
    if length data >= 1 then
        match vlsplit 1 data with
        | Error(z) -> Error(z)
        | Correct (res) ->
        let (certTypeListBytes,data) = res in
        let certTypeList = parseCertificateTypeList certTypeListBytes in
        match parseSigHashAlgVersion version data with
        | Error(z) -> Error(z)
        | Correct (res) ->
        let (sigAlgs,data) = res in
        if length data >= 2 then
            match vlparse 2 data with
            | Error(z) -> Error(z)
            | Correct  (distNamesBytes) ->
            let el = [] in
            match parseDistinguishedNameList distNamesBytes el with
            | Error(z) -> Error(z)
            | Correct (distNamesList) ->
            correct (certTypeList,sigAlgs,distNamesList)

        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(** A.4.3 Client Authentication and Key Exchange Messages *)

let encpmsBytesVersion version encpms =
    match version with
    | SSL_3p0 -> encpms
    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> vlbytes 2 encpms
#if tls13
    | TLS_1p3 -> unexpected "[encpmsBytesVersion] TLS 1.3 does not support RSA key exchange"
#endif

let parseEncpmsVersion version data =
    match version with
    | SSL_3p0 -> correct (data)
    | TLS_1p0 | TLS_1p1| TLS_1p2 ->
        if length data >= 2 then
            match vlparse 2 data with
            | Correct (encPMS) -> correct(encPMS)
            | Error(z) -> Error(z)
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
#if tls13
    | TLS_1p3 -> unexpected "[encpmsBytesVersion] TLS 1.3 does not support RSA key exchange"
#endif

let clientKeyExchangeBytes_RSA si encpms =
    let nencpms = encpmsBytesVersion si.protocol_version encpms in
    let mex = messageBytes HT_client_key_exchange nencpms in
        mex

let parseClientKeyExchange_RSA si data =
    parseEncpmsVersion si.protocol_version data

let clientKEXExplicitBytes_DH y =
    messageBytes HT_client_key_exchange y

let parseClientKEXExplicit_DH dhp data =
    let kxlen = match dhp with CommonDH.DHP_EC _ -> 1 | CommonDH.DHP_P _ -> 2 in
    if length data >= kxlen then
        match vlparse kxlen data with
        | Error(z) -> Error(z)
        | Correct(y) ->
            match CommonDH.parse dhp y with
            | None -> Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid DH key received")
            | Some(y) -> correct y
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

// Unused until we don't support DH ciphersuites.
let clientKEXImplicitBytes_DH = messageBytes HT_client_key_exchange empty_bytes
// Unused until we don't support DH ciphersuites.
let parseClientKEXImplicit_DH data =
    if length data = 0 then
        correct ( () )
    else
        Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

#if tls13
(* TLS 1.3 Client Key Exchange (Sec 7.4.2 of TLS 1.3 draft) *)

type tls13kex =
    | DHE of dhGroup * bytes

let tls13CKEOfferBytes kex =
    match kex with
    | DHE(group,gx) ->
        let kexb = abytes [|1uy|] in
        let groupb = dhGroupBytes group in
        let gxb = vlbytes 2 gx in
        kexb @| groupb @| gxb

let rec tls13CKEOffersBytes_int kexs =
    match kexs with
    | [] -> empty_bytes
    | h::t ->
        let hb = tls13CKEOfferBytes h in
        let remb = tls13CKEOffersBytes_int t in
        hb @| remb

let tls13CKEOffersBytes kexs =
    let b = tls13CKEOffersBytes_int kexs in
    let data = vlbytes 2 b in
    messageBytes HT_client_key_exchange data

let rec parseTLS13CKEOffers_int b =
    if equalBytes b empty_bytes then
        correct([])
    else
        let (kexb,b) = split b 1 in
        match cbytes kexb with
        | [| 1uy |] -> // DHE
            if length b < 3 then
                Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else
                (let groupb,b = split b 1 in
                match parseDHGroup groupb with
                | Error(x,y) ->
                    // Unknown group, parse and ignore this entry
                    (match vlsplit 2 b with
                    | Error(x,y) -> Error(x,y) // parsing error
                    | Correct(res) ->
                        let _,b = res in
                        parseTLS13CKEOffers_int b)
                | Correct(group) ->
                    match vlsplit 2 b with
                    | Error(x,y) -> Error(x,y)
                    | Correct(res) ->
                        (let gx,b = res in
                        match parseTLS13CKEOffers_int b with
                        | Error(x,y) -> Error(x,y)
                        | Correct(res) -> let res = DHE(group,gx) :: res in correct res))
        | _ ->
            // unsupported key exchange

            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let parseTLS13CKEOffers b =
    match vlparse 2 b with
    | Error(x,y) -> Error(x,y)
    | Correct(b) ->
        parseTLS13CKEOffers_int b

(* TLS 1.3 Server Key Exchange (Sec 7.4.3 of TLS 1.3 draft) *)

let tls13SKEDHEBytes gx = vlbytes 2 gx

let tls13SKEBytes kex =
    match kex with
    | DHE(group,gx) ->
        let data = tls13SKEDHEBytes gx in
        messageBytes HT_server_key_exchange data

let parseTLS13SKEDHE group b =
    match vlparse 2 b with
    | Error(x,y) -> Error(x,y)
    | Correct(gx) -> correct (DHE(group,gx))
#endif

(* Digitally signed struct *)

let digitallySignedBytes alg data pv =
    let tag = vlbytes 2 data in
    match pv with
#if tls13
    | TLS_1p3
#endif
    | TLS_1p2  ->
        let sigHashB = sigHashAlgBytes alg in
        sigHashB @| tag
    | SSL_3p0 | TLS_1p0 | TLS_1p1 -> tag

let parseDigitallySigned expectedAlgs payload pv =
    match pv with
#if tls13
    | TLS_1p3
#endif
    | TLS_1p2 ->
        if length payload >= 2 then
            let (recvAlgsB,sign) = Bytes.split payload 2 in
            match parseSigHashAlg recvAlgsB with
            | Error(z) -> Error(z)
            | Correct(recvAlgs) ->
                if sigHashAlg_contains expectedAlgs recvAlgs then
                    if length sign >= 2 then
                        match vlparse 2 sign with
                        | Error(z) -> Error(z)
                        | Correct(sign) -> correct(recvAlgs,sign)
                    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
                else Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    | SSL_3p0 | TLS_1p0 | TLS_1p1 ->
        if List.listLength expectedAlgs = 1 then
            if length payload >= 2 then
                match vlparse 2 payload with
                | Error(z) -> Error(z)
                | Correct(sign) ->
                correct(List.listHead expectedAlgs,sign)
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else unexpected "[parseDigitallySigned] invoked with invalid SignatureAndHash algorithms"

(* Server Key exchange *)

let parseDHEParams cs dhdb minSize payload =
    if isECDHECipherSuite cs then
        if length payload >= 7 then
            let (curve, point) = split payload 3 in
            match ECGroup.parse_curve curve with
            | None -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Unsupported curve")
            | Some(ecp) ->
                match vlsplit 1 point with
                | Error(z) -> Error(z)
                | Correct(rawpoint, payload) ->
                    match ECGroup.parse_point ecp rawpoint with
                    | None -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "Invalid EC point received")
                    | Some p -> correct (None, CommonDH.DHP_EC(ecp), {CommonDH.dhe_nil with dhe_ec = Some p;}, payload)
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
    else
        if length payload >= 2 then
            match vlsplit 2 payload with
            | Error(z) -> Error(z)
            | Correct(res) ->
            let (p,payload) = res in
            if length payload >= 2 then
                match vlsplit 2 payload with
                | Error(z) -> Error(z)
                | Correct(res) ->
                let (g,payload) = res in
                if length payload >= 2 then
                    match vlsplit 2 payload with
                    | Error(z) -> Error(z)
                    | Correct(res) ->
                    let (y,payload) = res in
#if tls13
                    let dhp = {dhp = p; dhg = g; dhq = empty_bytes; safe_prime = false} in
#else
                    // Check params and validate y
                    match DHGroup.checkParams dhdb minSize p g with
                    | Error(z) -> Error(z)
                    | Correct(res) ->
                        let (dhdb,dhp) = res in
                        match DHGroup.checkElement dhp y with
                        | None -> Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "Invalid DH key received")
                        | Some(y) ->
#endif
    #if verify

                            let p' = dhp.dhp in
    #endif
                            correct (Some dhdb, CommonDH.DHP_P(dhp), {CommonDH.dhe_nil with dhe_p = Some y}, payload)
                else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
            else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let serverKeyExchangeBytes_DHE dheb alg sign pv =
    let sign = digitallySignedBytes alg sign pv in
    let payload = dheb @| sign in
    messageBytes HT_server_key_exchange payload

let parseServerKeyExchange_DHE dhdb minSize pv cs payload =
    match parseDHEParams cs dhdb minSize payload with
    | Error(z) -> Error(z)
    | Correct(res) ->
        let (p,g,y,payload) = res in
        let allowedAlgs = default_sigHashAlg pv cs in
        (match parseDigitallySigned allowedAlgs payload pv with
        | Error(z) -> Error(z)
        | Correct(res) ->
            let (alg,signature) = res in
            correct(p,g,y,alg,signature))

let serverKeyExchangeBytes_DH_anon p y =
    let dehb = CommonDH.serializeKX p y in
    messageBytes HT_server_key_exchange dehb

let parseServerKeyExchange_DH_anon cs dhdb minSize payload =
    match parseDHEParams cs dhdb minSize payload with
    | Error(z) -> Error(z)
    | Correct(z) ->
        let (p,g,y,rem) = z in
        if length rem = 0 then
            correct(p,g,y)
        else
            Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* Certificate Verify *)

let makeCertificateVerifyBytes si (ms:PRF.masterSecret) alg skey data =
    // The returned "tag" variable is ghost, only used to avoid
    // existentials in formal verification.
    match si.protocol_version with
#if tls13
    | TLS_1p3
#endif
    | TLS_1p2 | TLS_1p1 | TLS_1p0 ->
        let tag = Sig.sign alg skey data in
        let payload = digitallySignedBytes alg tag si.protocol_version in
        let mex = messageBytes HT_certificate_verify payload in
        (mex,tag)
    | SSL_3p0 ->
#if verify
        failwith "unsuppoprted format"
#else
        let (sigAlg,_) = alg in
        let alg = (sigAlg,NULL) in
        let toSign = PRF.ssl_certificate_verify si ms sigAlg data in
        let tag = Sig.sign alg skey toSign in
        let payload = digitallySignedBytes alg tag si.protocol_version in
        let mex = messageBytes HT_certificate_verify payload in
        (mex,tag)
#endif

let certificateVerifyCheck si ms algs log payload =
    // The returned byte array is ghost, only used to avoid
    // existentials in formal verification.
    match parseDigitallySigned algs payload si.protocol_version with
    | Correct(res) ->
        let (alg,signature) = res in
        //let (alg,expected) =
        (match si.protocol_version with
#if tls13
        | TLS_1p3
#endif
        | TLS_1p2 | TLS_1p1 | TLS_1p0 ->
            (match Cert.get_chain_public_signing_key si.clientID alg with
            | Error(z) -> (false,alg,empty_bytes)
            | Correct(vkey) ->
                let res = Sig.verify alg vkey log signature in
                (res,alg,signature))
        | SSL_3p0 ->
            let (sigAlg,_) = alg in
            let alg = (sigAlg,NULL) in
            let expected = PRF.ssl_certificate_verify si ms sigAlg log in
            (match Cert.get_chain_public_signing_key si.clientID alg with
            | Error(z) -> (false,alg,empty_bytes)
            | Correct(vkey) ->
                let res = Sig.verify alg vkey expected signature in
                (res,alg,signature)))
    | Error(z) -> (false,(SA_RSA,SHA),empty_bytes)