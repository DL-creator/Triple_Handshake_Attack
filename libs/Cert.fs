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

module Cert

(* ------------------------------------------------------------------------ *)
open System.IO
open System 
open Bytes
open TLSConstants
open Error
open TLSError
open UntrustedCert
open CoreSig
open RSAKey

type chain = UntrustedCert.chain
type hint = UntrustedCert.hint
type cert = UntrustedCert.cert

type sign_cert = option<(chain * Sig.alg * Sig.skey)>
type enc_cert  = option<(chain * RSAKey.sk)>

(* ------------------------------------------------------------------------ *)

#if verify
let forall (test: (X509Certificate2 -> bool)) (chain : list<X509Certificate2>) : bool = failwith "for specification purposes only, unverified"
#else
let forall (test: (X509Certificate2 -> bool)) (chain : list<X509Certificate2>) : bool = Seq.forall test chain
#endif

let for_signing (sigkeyalgs : list<Sig.alg>) (h : hint) (algs : list<Sig.alg>) =
    match (find_sigcert_and_alg sigkeyalgs h algs) with
    | Some(cert_and_alg) ->
        let x509, (siga, hasha) = cert_and_alg in
        let alg = (siga, hasha) in
        (match x509_to_secret_key x509, x509_to_public_key x509 with
        | Some skey, Some pkey ->
            let chain = x509_chain x509 in

            if forall (x509_check_key_sig_alg_one sigkeyalgs) chain then
                let pk = Sig.create_pkey alg pkey in
                #if ideal
                if Sig.honest alg pk then
                    None //loading of honest keys not implemented yet.
                else
                    let sk = Sig.coerce alg pk skey in
                    Some (x509list_to_chain chain, alg, sk)
                #else
                Some (x509list_to_chain chain, alg, Sig.coerce alg pk skey)
                #endif
            else
                None
        | None, _ -> None
        | _, None -> None)
    | None -> None

(* ------------------------------------------------------------------------ *)

let for_key_encryption (sigkeyalgs : list<Sig.alg>) (h : hint) =
            match (find_enccert sigkeyalgs h) with
            | Some(x509) ->
                (match x509_to_secret_key x509, x509_to_public_key x509 with
                | Some (CoreSig.SK_RSA(smse)), Some(CoreSig.PK_RSA(pmpe)) ->
                    let (sm,se)=smse in
                    let (pm,pe)=pmpe in
                    let chain = x509_chain x509 in

                    if forall (x509_check_key_sig_alg_one sigkeyalgs) chain then
                        let pk = RSAKey.create_rsapkey (pmpe) in
                        #if ideal

                        if RSAKey.honest pk then
                            None //loading of honest keys not implemented yet.
                        else
                            let csk = CoreACiphers.RSASKey(smse) in
                            let sk = RSAKey.coerce pk csk in
                            Some (x509list_to_chain chain, sk)
                        #else
                        Some (x509list_to_chain chain, RSAKey.coerce pk (CoreACiphers.RSASKey(smse)))
                        #endif
                    else
                        None
                | None, _ -> None
                | _, None -> None
                | _, _ -> Error.unexpected "[for_key_encryption] unreachable pattern match")
            | None -> None

(* ------------------------------------------------------------------------ *)
let get_public_signing_key (c : cert) ((siga, _) as a : Sig.alg) : Result<Sig.pkey> =
    match cert_to_x509 c with
    | Some(x509) ->
            if x509_is_for_signing x509 then
                match siga, x509_to_public_key x509 with
                | SA_RSA, Some (k) -> Correct (Sig.create_pkey a k)
                | SA_DSA, Some (k) -> Correct (Sig.create_pkey a k)
                | _ -> Error(AD_unsupported_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate uses unknown signature algorithm or key")
            else
                Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate is not for signing")
    | None -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let get_public_encryption_key (c : cert) : Result<RSAKey.pk> =
    match cert_to_x509 c with
    | Some(x509) ->
            if x509_is_for_key_encryption x509 then
                match x509_to_public_key x509 with
                | Some (CoreSig.PK_RSA(pm, pe)) -> Correct (RSAKey.create_rsapkey (pm, pe))
                | _ -> Error(AD_unsupported_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate uses unknown key")
            else
                Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate is not for key encipherment")
    | None -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* ------------------------------------------------------------------------ *)

#if verify
let get_chain_public_signing_key (chain : chain) (a:Sig.alg) : Result<Sig.pkey> =
    failwith "unverified"

let get_chain_public_encryption_key (chain : chain) : Result<RSAKey.pk>=
    failwith "unverified"

#else
let get_chain_public_signing_key (chain : chain) a =
    match chain with
    | []     -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "This is likely a bug, please report it")
    | c :: _ -> get_public_signing_key c a

let get_chain_public_encryption_key (chain : chain) =
    match chain with
    | []     -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "This is likely a bug, please report it")
    | c :: _ -> get_public_encryption_key c
#endif

let signing_gen (a:Sig.alg) : Sig.pkey =
    let pk,sk = Sig.gen a in
    pk

(* ------------------------------------------------------------------------ *)

let validate_cert_chain (sigkeyalgs : list<Sig.alg>) (chain : chain) =
    validate_x509_chain sigkeyalgs chain

(* ------------------------------------------------------------------------ *)
#if verify
let get_hint (chain : chain) : option<hint> =
    failwith "unverified"
#else
let get_hint (chain : chain) : option<hint> =
    match chain_to_x509list chain with
    | Some x509list ->
        (match x509list with
        | []     -> None
        | c :: _ -> Some (get_name_info c))
    | None -> None
#endif

(* ------------------------------------------------------------------------ *)
let is_chain_for_signing (chain : chain) =
    match chain with [] -> false| c :: _ -> is_for_signing c

let is_chain_for_key_encryption (chain : chain) =
    match chain with [] -> false| c :: _ -> is_for_key_encryption c

(* ---- TLS-specific encoding ---- *)
let consCertificateBytes c a =
    let cert = vlbytes 3 c in
    cert @| a

#if verify
let certificateListBytes (certs: chain) : bytes =
    failwith "unverified"

let parseCertificateListInt (toProcess:bytes) (list:chain) : Result<chain> =
    failwith "unverified"

let parseCertificateList (toProcess:bytes): Result<chain> =
    failwith "unverified"
#else
let certificateListBytes certs =
    let unfolded = List.foldBack consCertificateBytes certs empty_bytes in
    vlbytes 3 unfolded

let rec parseCertificateListInt toProcess parsed =
    if equalBytes toProcess empty_bytes then
        correct(parsed)
    else
        if length toProcess >= 3 then
            match vlsplit 3 toProcess with
            | Error(x,y) -> Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ y)
            | Correct (res) ->
                let (nextCert,toProcess) = res in
                let parsed = parsed @ [nextCert] in
                parseCertificateListInt toProcess parsed
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let parseCertificateList toProcess = parseCertificateListInt toProcess []
#endif 

/// Load a PEM or DER-encoded certificate chain from disk
/// and return it as a Cert.chain (UntrustedCert.chain).
let chainFromFile (path: string) : chain =
    let isPem = fun (s: string) -> s.Contains("-----BEGIN CERTIFICATE-----") in

    if System.IO.Path.GetExtension(path).ToLower() = ".der" then
        let rawDer = System.IO.File.ReadAllBytes(path) in
        let derBytes = Bytes.abytes rawDer in
        match parseCertificateList derBytes with
        | Correct chain -> chain
        | Error (_, msg) -> failwithf "chainFromFile parse error: %s" msg
    else
        let text = System.IO.File.ReadAllText(path) in
        if not (isPem text) then
            failwithf "File does not appear to be PEM or DER: %s" path
        else
            let matches =
                System.Text.RegularExpressions.Regex.Matches(
                    text,
                    "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                    System.Text.RegularExpressions.RegexOptions.Singleline)
            in

            if matches.Count = 0 then
                failwithf "No valid PEM certificates found in: %s" path
            else
                let derCerts =
                    [ for m in matches ->
                        let base64 = m.Groups.[1].Value.Replace("\r", "").Replace("\n", "").Trim() in
                        base64 |> System.Convert.FromBase64String |> Bytes.abytes ]
                in
                let certList = certificateListBytes derCerts in
                match parseCertificateList certList with
                | Correct chain -> chain
                | Error (_, msg) -> failwithf "chainFromFile parse error: %s" msg
