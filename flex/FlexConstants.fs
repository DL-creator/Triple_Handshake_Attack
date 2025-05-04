(*
 * Copyright 2015 INRIA and Microsoft Corporation
 * Licensed under the Apache License, Version 2.0
 *)

#light "off"

module FlexTLS.FlexConstants

open Bytes
open Error
open TLSInfo
open TLSConstants
open CoreKeys
open FlexTypes

let defaultDHParams : CoreKeys.dhparams = {
    dhp = Bytes.utf8 (
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1" +
        "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9" +
        "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561" +
        "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735" +
        "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB" +
        "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19" +
        "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73" +
        "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA" +
        "886B423861285C97FFFFFFFFFFFFFFFF"
    );
    dhg = Bytes.abyte 0x02uy;  // generator = 2
    dhq = Bytes.empty_bytes;  // not provided in ffdhe2048, so use empty
    safe_prime = true;
}



/// Module for constant values and initialization values
type FlexConstants =
    class

    // ---- TLS settings ----
    static member defaultTCPPort = 443
    static member defaultTCPMaliciousPort = 6666
    static member defaultProtocolVersion = TLS_1p2
    static member defaultFragmentationPolicy = All(fragmentLength)
    static member defaultECDHcurve = ECC_P256
    static member defaultECDHcurveCompression = false
    static member minECDHSize = 256

    // ---- Ciphersuites ----
    static member defaultRSACiphersuites = [
        TLS_RSA_WITH_AES_256_GCM_SHA384;
        TLS_RSA_WITH_AES_128_GCM_SHA256;
        TLS_RSA_WITH_AES_256_CBC_SHA256;
        TLS_RSA_WITH_AES_128_CBC_SHA256;
        TLS_RSA_WITH_AES_256_CBC_SHA;
        TLS_RSA_WITH_AES_128_CBC_SHA;
        TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        TLS_RSA_WITH_RC4_128_SHA;
        TLS_RSA_WITH_RC4_128_MD5;
        TLS_RSA_WITH_NULL_SHA256;
        TLS_RSA_WITH_NULL_SHA;
        TLS_RSA_WITH_NULL_MD5;
    ]

    static member sigAlgs_RSA = [
        (SA_RSA, SHA);
        (SA_RSA, SHA256);
        (SA_RSA, MD5SHA1);
        (SA_RSA, NULL);
    ]

    // ---- Default minimal parameters ----
    static member defaultECDHParams = CommonDH.DHP_EC(ECGroup.getParams FlexConstants.defaultECDHcurve)

    static member nullKexECDH = {
        curve = FlexConstants.defaultECDHcurve;
        comp = FlexConstants.defaultECDHcurveCompression;
        x = empty_bytes;
        ecp_x = (empty_bytes, empty_bytes);
        ecp_y = (empty_bytes, empty_bytes);
    }

    static member nullFClientHello : FClientHello = {
        pv = Some(TLS_1p2);
        rand = empty_bytes;
        sid = None;
        ciphersuites = Some([]);
        comps = Some([]);
        ext = None;
        payload = empty_bytes;
    }

    static member nullFServerHello : FServerHello = {
        pv = Some(TLS_1p2);
        rand = empty_bytes;
        sid = None;
        ciphersuite = None;
        comp = NullCompression;
        ext = None;
        payload = empty_bytes;
    }

    static member sigAlgs_ALL = [(SA_RSA, SHA256);(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL);(SA_DSA, SHA)]

    static member nullFHelloRequest : FHelloRequest = {
        payload = empty_bytes;
    }

    static member nullFCertificate : FCertificate = {
        chain = [];
        payload = empty_bytes;
    }

    static member nullFCertificateRequest : FCertificateRequest = {
        certTypes = [RSA_sign; DSA_sign];
        sigAlgs = [];
        names = [];
        payload = empty_bytes;
    }

    static member nullFCertificateVerify : FCertificateVerify = {
        sigAlg = (SA_RSA, SHA);
        signature = empty_bytes;
        payload = empty_bytes;
    }

    static member nullFServerKeyExchangeDHx : FServerKeyExchange = {
        sigAlg = (SA_RSA, SHA);
        signature = empty_bytes;
        kex = DH({ pg = (empty_bytes, empty_bytes); x = empty_bytes; gx = empty_bytes; gy = empty_bytes });
        payload = empty_bytes;
    }

    static member nullFServerHelloDone : FServerHelloDone = {
        payload = empty_bytes;
    }

    static member nullFClientKeyExchangeRSA : FClientKeyExchange = {
        kex = RSA(empty_bytes);
        payload = empty_bytes;
    }

    static member nullFClientKeyExchangeDH : FClientKeyExchange = {
        kex = DH({ pg = (empty_bytes, empty_bytes); x = empty_bytes; gx = empty_bytes; gy = empty_bytes });
        payload = empty_bytes;
    }

    static member nullFChangeCipherSpecs : FChangeCipherSpecs = {
        payload = HandshakeMessages.CCSBytes;
    }

    static member nullFFinished : FFinished = {
        verify_data = empty_bytes;
        payload = empty_bytes;
    }

    static member nullNegotiatedExtensions = {
        ne_extended_padding = false;
        ne_extended_ms = false;
        ne_renegotiation_info = None;
        ne_negotiated_dh_group = None;
        ne_supported_curves = None;
        ne_supported_point_formats = None;
        ne_server_names = None;
    }

    static member nullSessionInfo = {
        clientID = [];
        clientSigAlg = (SA_RSA, SHA);
        serverSigAlg = (SA_RSA, SHA);
        client_auth = false;
        serverID = [];
        sessionID = empty_bytes;
        protocol_version = TLS_1p2;
        cipher_suite = nullCipherSuite;
        compression = NullCompression;
        extensions = FlexConstants.nullNegotiatedExtensions;
        init_crand = empty_bytes;
        init_srand = empty_bytes;
        session_hash = empty_bytes;
        pmsId = noPmsId;
    }

    static member nullSecrets = {
        pri_key = PK_None;
        kex = RSA(empty_bytes);
        pms = empty_bytes;
        ms = empty_bytes;
        epoch_keys = (empty_bytes, empty_bytes);
    }

    static member nullNextSecurityContext = {
        si = FlexConstants.nullSessionInfo;
        crand = empty_bytes;
        srand = empty_bytes;
        secrets = FlexConstants.nullSecrets;
        offers = [];
    }

     static member names_of_cipherSuites css =
        match css with
        | [] -> correct []
        | h::t ->
            if contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV [h] then
                match FlexConstants.names_of_cipherSuites t with
                | Error(x,y) -> Error(x,y)
                | Correct(rem) -> correct(rem)
            else
                match name_of_cipherSuite h with
                | Error(x,y) -> Error(x,y)
                | Correct(n) ->
                    match FlexConstants.names_of_cipherSuites t with
                    | Error(x,y) -> Error(x,y)
                    | Correct(rem) -> correct (n::rem)

    end
