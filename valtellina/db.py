import argparse
import json
import os
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "segnalazioni.json"
# DB_PATH = BASE_DIR / "da_segnalare.json"
INPUT_PATH = BASE_DIR / "input.ts"


def read_db():
    if not DB_PATH.exists():
        return {}

    with DB_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def write_db(db):
    # Ordina applicativi e macchine e rimuove duplicati
    db = {
        app: sorted(set(machines))
        for app, machines in sorted(db.items())
    }

    with DB_PATH.open("w", encoding="utf-8") as file:
        json.dump(
            db,
            file,
            indent=2,
            ensure_ascii=False
        )


def read_input_file(file_path):
    result = {}

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:

            line = line.strip()

            if not line:
                continue

            app, machines = line.split(":", 1)

            machines = [
                machine.strip()
                for machine in machines.split(",")
                if machine.strip()
            ]

            result.setdefault(
                app.strip(),
                []
            ).extend(machines)

    return result


def update_db():
    db = read_db()
    a = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
        capture_output=True,
        text=True,
        check=True
    ).stdout.strip()
    
    new_data = json.loads(a)
    for app, machines in new_data.items():
        if not machines:
            continue
        

        filename = app.split("\\")[-1]
        
        print(f"{filename}: ricevute {len(machines)} macchine")
        
        if filename not in db:
            db[filename] = []

        db[filename].extend(machines)

    write_db(db)


def db_to_kql():
    db = read_db()

    # json_data = json.dumps(
    #     db,
    #     indent=2,
    #     ensure_ascii=False
    # )
    a = f"""
let app = dynamic();
let macchineSegnalate = dynamic({db});
let appname = toscalar (
    print app = app
    | mv-expand app
    | extend AppName = extract(@"([^\\\\]+\.exe|dll)$", 1, tostring(app))
    | where isnotempty(AppName)
    | summarize make_set(AppName)
    );
CommonSecurityLog //ricerca
| where TimeGenerated > ago(30d)
| where DeviceVendor == "Fortinet" and DeviceProduct == "FortiEDR"
| parse-kv AdditionalExtensions as (EventCommandLine: string, Deployment: string, StackHashes: string, EventTarget: string) with (kv_delimiter = "=", pair_delimiter = ";")
| where FileName has_any(appname) //and SourceHostName !in(macchineSegnalate)
| extend EventTarget = split(EventTarget, ", ")
| project-reorder
    TimeGenerated,
    Activity,
    SourceHostName,
    DeviceTranslatedAddress,
    DeviceCustomString3,
    FileName,
    FilePath,
    FileHash,
    EventCommandLine,
    Deployment,
    StackHashes,
    DeviceAction,
    EventTarget
//| where FileName in(bag_keys(macchineSegnalate))
| summarize
    MacchineTrovate = make_set(SourceHostName),
    MacchineSegnalate = take_any(macchineSegnalate[FileName]),
    makeset(FileHash),
    makeset(EventTarget),
    makeset(EventCommandLine),
    makeset(SourceHostName),
    makeset(SourceUserName, 1)
    by FileName
| extend MacchineDaSegnalare = set_difference(MacchineTrovate, MacchineSegnalate)| project FileName, MacchineDaSegnalare
| where array_length( MacchineDaSegnalare) > 0
| extend bag = bag_pack(FileName, MacchineDaSegnalare)| summarize  json=make_bag(bag)
// INIZIA COMMENTO
// | extend
//     hashes = strcat("- **", FileName, "**: ", set_FileHash),
//     utenti = strcat("- Account ", set_SourceUserName, " esegue lo script ", FileName),
//     macchine = strcat("- **", FileName, "**: ", set_SourceHostName)
// | summarize makeset(macchine), make_set(hashes), makeset(utenti)
//FINE COMMENTO
    """
    return a


def copy_to_clipboard(text):
    subprocess.run(
        ["clip"],
        input=text,
        text=True
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "command",
        choices=["update", "show", "copy"]
    )

    parser.add_argument(
        "data",
        nargs="?"
    )

    args = parser.parse_args()

    if args.command == "update":
        update_db()
        print("Database aggiornato.")

    elif args.command == "show":
        print(db_to_kql())

    elif args.command == "copy":
        copy_to_clipboard(db_to_kql())
        print("KQL copiata negli appunti.")


if __name__ == "__main__":
    main()