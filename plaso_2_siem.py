#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import os
import traceback
from elastic_uploader import ElasticUploader

from plaso_processors.base_processor import BaseEventProcessor
from plaso_processors.evtx_processor import PlasoEvtxProcessor
from plaso_processors.registry_processor import PlasoRegistryProcessor
from plaso_processors.mft_processor import PlasoMftProcessor
from plaso_processors.lnk_processor import PlasoLnkProcessor
from plaso_processors.prefetch_processor import PlasoPrefetchProcessor
from plaso_processors.srum_processor import PlasoSrumProcessor
from plaso_processors.browser_history_processor import PlasoBrowserHistoryProcessor
from plaso_processors.amcache_processor import PlasoAmcacheProcessor
from plaso_processors.generic_processor import PlasoGenericProcessor
from plaso_processors.appcompatcache_processor import PlasoAppCompatCacheProcessor
from plaso_processors.userassist_processor import PlasoUserAssistProcessor
from plaso_processors.runkey_processor import PlasoRunKeyProcessor
from plaso_processors.usb_processor import PlasoUsbProcessor
from plaso_processors.mru_processor import PlasoMruProcessor


class PlasoPipeline:
    """
    Orchestre la lecture d'une timeline Plaso (jsonl) et l'envoi des événements
    parsés à Elasticsearch via des processeurs dédiés.
    """

    def __init__(self, case_name, machine_name, timeline_path, es_hosts, es_user, es_pass, chunk_size, verify_ssl):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = machine_name.lower().replace(" ", "_")
        self.timeline_path = timeline_path
        self.chunk_size = chunk_size
        self.index_prefix = f"{self.case_name}_{self.machine_name}"

        self.uploader = ElasticUploader(es_hosts, es_user, es_pass, verify_ssl)

        self.parser_regex_map = {
            "srum": re.compile(r'esedb/srum'),
            "amcache": re.compile(r'winreg/amcache'),
            "appcompatcache": re.compile(r'appcompatcache'),
            "runkey": re.compile(r'winreg/windows_run'),
            "usb": re.compile(r'winreg/windows_usb_devices'),
            "mru": re.compile(r'winreg/(bagmru|mrulistex)'),
            "userassist": re.compile(r'userassist'),  # <-- NOUVELLE REGEX (avant 'hive')
            "browser_history": re.compile(r'(sqlite/((chrome|firefox|edge).*history))'),
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),  # <-- Doit être APRÈS les 'winreg' spécifiques
            "db": re.compile(r'(sqlite)|(esedb)'),  # Fallback générique
            "lnk": re.compile(r'lnk'),
            "prefetch": re.compile(r'prefetch'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }

        self.processors = {
            "srum": PlasoSrumProcessor(),
            "amcache": PlasoAmcacheProcessor(),
            "appcompatcache": PlasoAppCompatCacheProcessor(),
            "runkey": PlasoRunKeyProcessor(),
            "usb": PlasoUsbProcessor(),
            "mru": PlasoMruProcessor(),
            "userassist": PlasoUserAssistProcessor(),
            "browser_history": PlasoBrowserHistoryProcessor(),
            "evtx": PlasoEvtxProcessor(),
            "hive": PlasoRegistryProcessor(),
            "mft": PlasoMftProcessor(),
            "lnk": PlasoLnkProcessor(),
            "prefetch": PlasoPrefetchProcessor(),
            "other": PlasoGenericProcessor()
        }
        print("[*] Processeurs initialisés.")

    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def identify_artefact_type(self, event: dict) -> str:
        parser = event.get("parser", "")
        for key, value_regex in self.parser_regex_map.items():
            if re.search(value_regex, parser):
                return key
        return "other"

    def run(self):
        print("\n--- CONFIGURATION ---")
        print(f"  Fichier Timeline : {self.timeline_path}")
        print(f"  Index Prefix     : {self.index_prefix}")
        print(f"  Taille des Lots  : {self.chunk_size}")
        print("---------------------\n")

        # Générer et envoyer les actions
        actions_generator = self._process_timeline_file()
        self.uploader.streaming_bulk_upload(actions_generator, self.chunk_size)

    def _process_timeline_file(self):
        print(f"[*] Début de la lecture du fichier timeline : {self.timeline_path}")
        it = 0
        try:
            with open(self.timeline_path, 'r', encoding='utf-8') as f:
                for line in f:
                    it += 1

                    if it % (self.chunk_size * 10) == 0:  # Log de progression
                        print(f"    ... Ligne {it} atteinte")
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    try:
                        event = json.loads(stripped_line)
                        event["event_raw_string"] = stripped_line
                        artefact_type = self.identify_artefact_type(event)
                        processor = self.processors.get(artefact_type, self.processors["other"])
                        processed_doc, index_type_key = processor.process_event(event)
                        index_name = f"{self.index_prefix}_{index_type_key}"

                        yield {
                            "_index": index_name,
                            "_source": processed_doc
                        }

                    except json.JSONDecodeError:
                        print(f"[Attention] Ligne JSON invalide ignorée (ligne {it})")
                        continue
                    except Exception as e:
                        print(f"[ERREUR] Échec du traitement de la ligne {it}. Erreur: {e}")
                        print(f"  Ligne: {stripped_line[:200]}...")
                        traceback.print_exc()

        except FileNotFoundError:
            print(f"[ERREUR FATALE] Le fichier timeline '{self.timeline_path}' n'a pas été trouvé.")
            exit(1)
        except Exception as e:
            print(f"[ERREUR FATALE] Échec de la lecture du fichier. Erreur: {e}")
            traceback.print_exc()
            exit(1)

        print(f"[*] Lecture du fichier terminée. Total de {it} lignes traitées.")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Processeur de timeline Plaso (jsonl) pour envoi vers Elasticsearch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--timeline", required=True,
                        help="Chemin vers le fichier timeline Plaso au format JSON Lines (jsonl).")
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas (utilisé dans le nom de l'index).")
    parser.add_argument("-m", "--machine-name", required=True,
                        help="Nom de la machine (utilisé dans le nom de l'index).")
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Elasticsearch, séparés par des virgules.")
    parser.add_argument("--es-user", default="elastic", help="Nom d'utilisateur pour Elasticsearch.")
    parser.add_argument("--es-pass", default="changeme", help="Mot de passe pour Elasticsearch.")
    parser.add_argument("--chunk-size", type=int, default=1000, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--verify-ssl", action="store_true", dest="verify_ssl", default=False,
                        help="Active la vérification du certificat SSL (désactivée par défaut).")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    try:
        pipeline = PlasoPipeline(
            case_name=args.case_name,
            machine_name=args.machine_name,
            timeline_path=args.timeline,
            es_hosts=args.es_hosts.split(','),  # Convertir en liste
            es_user=args.es_user,
            es_pass=args.es_pass,
            chunk_size=args.chunk_size,
            verify_ssl=args.verify_ssl
        )
        pipeline.run()
    except (ConnectionError) as e:
        print(f"\n[ERREUR DE CONNEXION] {e}")
    except Exception as e:
        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()


"""
parsers
parser": "custom_destinations/lnk"
parser": "custom_destinations/lnk/shell_items"
parser": "esedb/msie_webcache"
parser": "esedb/srum"
parser": "filestat"
parser": "lnk"
parser": "lnk/shell_items"
parser": "mft"
parser": "olecf/olecf_automatic_destinations"
parser": "olecf/olecf_automatic_destinations/lnk"
parser": "olecf/olecf_automatic_destinations/lnk/shell_items"
parser": "olecf/olecf_default"
parser": "onedrive_log"
parser": "pe"
parser": "prefetch"
parser": "sqlite/chrome_27_history"
parser": "sqlite/windows_timeline"
parser": "text/setupapi"
parser": "utmp"
parser": "winevtx"
parser": "winreg/amcache"
parser": "winreg/appcompatcache"
parser": "winreg/bagmru"
parser": "winreg/bagmru/shell_items"
parser": "winreg/bam"
parser": "winreg/explorer_mountpoints2"
parser": "winreg/explorer_programscache"
parser": "winreg/mrulistex_string"
parser": "winreg/mrulistex_string_and_shell_item"
parser": "winreg/mrulist_string"
parser": "winreg/msie_zone"
parser": "winreg/networks"
parser": "winreg/userassist"
parser": "winreg/windows_boot_execute"
parser": "winreg/windows_run"
parser": "winreg/windows_sam_users"
parser": "winreg/windows_services"
parser": "winreg/windows_shutdown"
parser": "winreg/windows_task_cache"
parser": "winreg/windows_timezone"
parser": "winreg/windows_typed_urls"
parser": "winreg/windows_version"
parser": "winreg/winlogon"
parser": "winreg/winreg_default"
"""