module DHGroup

open Bytes
open Error
open TLSError

type elt = bytes
let load_default_params (pem_file:string) (dhdb:DHDB.dhdb) (_: int * int) : DHDB.dhdb * CoreKeys.dhparams =
  failwith "specification only"
  
let genElement dhp: elt =
    let (_, e) = CoreDH.gen_key dhp
    e

let checkParams minSize p g =
    match CoreDH.check_params 80 minSize p g with
    | Error(x) -> Error(AD_insufficient_security, x)
    | Correct(dhp) -> correct dhp

let checkElement dhp (b:bytes) : option<elt> =
    if CoreDH.check_element dhp b then
        Some(b)
    else
        None

let defaultDHparams file dhdb minSize =
    let (dhdb,dhp) = load_default_params file dhdb minSize in
#if ideal
    let dhp = pp(dhp) in
#endif
    (dhdb,dhp)