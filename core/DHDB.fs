module DHDB

open Bytes

// Dummy DH parameter database, clean for your project

type dhdb = unit

type dhparams = { p : bytes; g : bytes }

type dhparamsDB = {
    dhe2432: dhparams;
    dhe3072: dhparams;
    dhe4096: dhparams;
    dhe6144: dhparams;
    dhe8192: dhparams;
}

// Create a dummy DH parameter database
let create () : dhparamsDB =
    let p = createBytes 10 0
    let g = createBytes 1 2
    {
        dhe2432 = { p = p; g = g };
        dhe3072 = { p = p; g = g };
        dhe4096 = { p = p; g = g };
        dhe6144 = { p = p; g = g };
        dhe8192 = { p = p; g = g };
    }

// Lookup a DH group by key size
let lookup (db: dhparamsDB) (size: int) : dhparams option =
    match size with
    | 2432 -> Some db.dhe2432
    | 3072 -> Some db.dhe3072
    | 4096 -> Some db.dhe4096
    | 6144 -> Some db.dhe6144
    | 8192 -> Some db.dhe8192
    | _ -> None
