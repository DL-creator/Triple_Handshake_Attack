module CommonDH

open Bytes
open Error
open TLSConstants
open CoreKeys

type element = {
 dhe_p  : DHGroup.elt option;
 dhe_ec : ECGroup.point option;
}

let dhe_nil = {
 dhe_p  = None;
 dhe_ec = None;
}

type secret = Key of bytes

type parameters =
| DHP_P of dhparams
| DHP_EC of ecdhparams

exception Invalid_DH

let leak   (p:parameters) (e:element) (Key(b)) = b
let coerce (p:parameters) (e:element) b = Key(b)

let get_p (e:element) =
    match e with
    | {dhe_p = Some x; dhe_ec = None; } -> x
    | _ -> raise Invalid_DH

let get_ec (e:element) =
    match e with
    | {dhe_p = None; dhe_ec = Some x; } -> x
    | _ -> raise Invalid_DH

let serializeKX (p:parameters) (e:element) : bytes =
    match p with
    | DHP_P(dhp)  -> vlbytes 2 dhp.dhp @|
                     vlbytes 2 dhp.dhg @|
                     vlbytes 2 (get_p e)
    | DHP_EC(ecp) -> abyte 3uy (* Named curve *)  @|
                     ECGroup.curve_id ecp         @|
                     ECGroup.serialize_point ecp (get_ec e)

let checkParams (p:parameters) =
    match p with
    | DHP_P(dhp) ->
        correct (None, p)  // We don't check DH params anymore
    | DHP_EC(ecp) ->
        correct (None, p)

let checkElement (p:parameters) (e:element) : element option =
    match (p, e.dhe_p, e.dhe_ec) with
    | DHP_P(dhp), Some b, None ->
        match DHGroup.checkElement dhp b with
        | None -> None
        | Some x -> Some {dhe_nil with dhe_p = Some x}
    | DHP_EC(ecp), None, Some p ->
        match ECGroup.checkElement ecp p with
        | None -> None
        | Some p -> Some {dhe_nil with dhe_ec = Some p}
    | _ -> failwith "impossible"

let parse (p:parameters) (b:bytes) =
    match p with
    | DHP_P(dhp) -> Some {dhe_nil with dhe_p = Some b}
    | DHP_EC(ecp) ->
        (match ECGroup.parse_point ecp b with
        | None -> None
        | Some ecp -> Some {dhe_nil with dhe_ec = Some ecp})
