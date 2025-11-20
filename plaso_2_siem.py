#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import os
import traceback
from elastic_uploader import ElasticUploader
from types import GeneratorType  # Importation pour identifier explicitement les générateurs

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

        # MAPPING VERS LES NOUVEAUX INDEX PLUS LARGES
        # La clé est le type d'artefact (pour sélectionner le bon processeur)
        # La valeur est la regex Plaso pour identifier l'artefact.
        self.parser_regex_map = {
            # EVTX
            "evtx": re.compile(r'winevtx'),

            # HIVE (Registre Windows)
            "runkey": re.compile(r'winreg/windows_run'),
            "usb": re.compile(r'winreg/windows_usb_devices'),
            "mru": re.compile(r'winreg/(bagmru|mrulistex)'),
            "hive": re.compile(r'winreg'),  # <-- Doit être APRÈS les 'winreg' spécifiques

            # PROCESS (Artefacts d'exécution)
            "srum": re.compile(r'esedb/srum'),
            "amcache": re.compile(r'winreg/amcache'),
            "appcompatcache": re.compile(r'appcompatcache'),
            "prefetch": re.compile(r'prefetch'),
            "userassist": re.compile(r'userassist'),

            # BROWSER_ARTEFACTS
            "browser_history": re.compile(r'(sqlite/((chrome|firefox|edge).*history))'),

            # FILES (Artefacts de système de fichiers)
            "lnk": re.compile(r'lnk'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)'),

            # OTHER / FALLBACK
            "other": re.compile(r'.*')  # Prend tout le reste
        }

        # Dictionnaire pour mapper le type d'artefact (clé du processeur) au nom de l'INDEX CONSOLIDÉ
        self.index_category_map = {
            "evtx": "evtx",
            "runkey": "hive",
            "usb": "hive",
            "mru": "hive",  # Ajouté aux HIVE
            "hive": "hive",
            "srum": "process",
            "amcache": "process",
            "appcompatcache": "process",
            "prefetch": "process",
            "userassist": "process",
            "browser_history": "browser_artefacts",
            "lnk": "files",
            "mft": "files",
            "other": "others"
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
        # IMPORTANT: Vérifier les regex dans l'ordre de la map pour que les plus spécifiques passent d'abord
        for key, value_regex in self.parser_regex_map.items():
            if re.search(value_regex, parser):
                return key
        # Si rien n'est trouvé (ne devrait pas arriver avec la dernière regex `.*`),
        # on retourne 'other'
        return "other"

    def run(self):
        print("\n--- CONFIGURATION ---")
        print(f"  Fichier Timeline : {self.timeline_path}")
        print(f"  Index Prefix     : {self.index_prefix}")
        print(f"  Taille des Lots  : {self.chunk_size}")
        print("---------------------\n")

        # Générer et envoyer les actions
        actions_generator = self._process_timeline_file()

        # Mettre en place les templates ES pour les nouvelles catégories
        self.uploader.setup_templates(
            evtx=f"{self.index_prefix}_evtx",
            hive=f"{self.index_prefix}_hive",
            process=f"{self.index_prefix}_process",
            files=f"{self.index_prefix}_files",
            browser_artefacts=f"{self.index_prefix}_browser_artefacts",
            others=f"{self.index_prefix}_others"
        )

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

                        artefact_type_key = self.identify_artefact_type(event)
                        processor = self.processors.get(artefact_type_key, self.processors["other"])

                        # Le résultat peut être un générateur (MRU) ou un tuple unique (les autres)
                        processor_result = processor.process_event(event)

                        # CORRECTION FINALE : Distinguer le générateur du tuple simple.
                        # Le PlasoMftProcessor renvoie un tuple de 2, qui est aussi un itérable.
                        if isinstance(processor_result, GeneratorType):
                            # C'est un générateur (cas MRU dénormalisé)
                            events_to_yield = processor_result
                        elif isinstance(processor_result, tuple) and len(processor_result) == 2:
                            # C'est un tuple simple (document, clé_specifique) - C'est le cas MFT, LNK, etc.
                            events_to_yield = [processor_result]
                        else:
                            # Cas d'erreur : le processeur a retourné un type incorrect.
                            print(
                                f"[Attention] Le processeur '{artefact_type_key}' a retourné un résultat inattendu: {type(processor_result)}. Traitement générique de l'erreur.")
                            processed_doc = {"message": f"Processor '{artefact_type_key}' returned malformed result.",
                                             "raw_event": event.get("event_raw_string")}
                            specific_index_key = "other"
                            events_to_yield = [(processed_doc, specific_index_key)]

                        for item in events_to_yield:
                            try:
                                # Tenter l'unpacking. C'est ici que l'erreur 'too many values' se produit.
                                processed_doc, specific_index_key = item
                            except ValueError as ve:
                                # Capture de l'erreur d'unpacking (ex: 3 éléments au lieu de 2 dans un générateur/itérable)
                                print(f"[ERREUR D'UNPACKING] Échec à la ligne {it} ({artefact_type_key}). Erreur: {ve}")
                                # Créer un document d'erreur pour ne pas perdre la donnée
                                error_doc = {
                                    "message": f"Unpacking error: {ve}. Original item: {item}",
                                    "raw_event_line": stripped_line,
                                    "artefact_type": "error_data"
                                }
                                specific_index_key = "other"
                                processed_doc = error_doc
                            except Exception as e:
                                # Autres erreurs inattendues durant l'itération
                                print(f"[ERREUR CRITIQUE] Échec à la ligne {it} ({artefact_type_key}). Erreur: {e}")
                                error_doc = {
                                    "message": f"Critical iteration error: {e}",
                                    "raw_event_line": stripped_line,
                                    "artefact_type": "critical_error"
                                }
                                specific_index_key = "other"
                                processed_doc = error_doc

                            # CONSERVATION DE LA CLÉ SPÉCIFIQUE DANS LE DOCUMENT
                            processed_doc["artefact_type"] = specific_index_key

                            # DÉTERMINATION DE L'INDEX CONSOLIDÉ
                            index_category_key = self.index_category_map.get(specific_index_key, "others")

                            index_name = f"{self.index_prefix}_{index_category_key}"

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