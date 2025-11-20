#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from .base_processor import BaseEventProcessor


class PlasoRegistryProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements de Registre (winreg).\n
    MODIFIÉ: Dénormalise les événements winreg_default (qui contiennent la liste 'values')\n
    en créant un document ELK pour chaque valeur de Registre trouvée.\n
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Registre")
        self.HIVE_FILE_MAP = {
            r'SOFTWARE': "software",
            r'SYSTEM': "system",
            r'SECURITY': "security",
            r'SAM': "sam",
            r'NTUSER\.DAT': "ntuser",
            r'UsrClass\.dat': "usrclass"
        }

    def get_specific_hive_type(self, original_filename):
        if not original_filename: return None
        for pattern, log_type in self.HIVE_FILE_MAP.items():
            if re.search(pattern, original_filename, re.IGNORECASE):
                return log_type
        return None

    def process_event(self, event: dict):  # -> (dict, str) ou Generator
        """
        Traite un événement de Registre de Plaso. Retourne un générateur de documents (dict, str).
        """

        # 1. Pré-traitement du Timestamp et de la Hive
        try:
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                es_timestamp = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                es_timestamp = self._format_dt_to_es(dt_plaso)

            filename = event.get("filename", "")
            specific_type = self.get_specific_hive_type(filename)

            base_doc = {
                "estimestamp": es_timestamp,
                "key_path": event.get("key_path"),
                "filename": filename,
                "parser": event.get("parser"),
                "data_type": event.get("data_type"),
                "hive_type": specific_type if specific_type else "unknown_hive"
            }

            values = event.get("values")

            # 2. Cas de Dénormalisation (Liste de valeurs)
            # L'événement contient le champ 'values', il faut le décomposer
            if isinstance(values, list) and len(values) > 0:

                # Supprimer la liste des valeurs originales pour ne pas l'indexer
                event.pop("values", None)

                for value_entry in values:
                    if not isinstance(value_entry, dict):
                        continue

                    processed_doc = base_doc.copy()

                    # Champs spécifiques à la valeur
                    processed_doc["reg_value_name"] = value_entry.get("name")
                    processed_doc["reg_value_data"] = value_entry.get("data")
                    processed_doc["reg_value_type"] = value_entry.get("data_type")
                    #processed_doc["message"] = event.get("message")
                    # Nettoyage final du document généré
                    self.drop_useless_fields(processed_doc)

                    yield processed_doc, "hive"

                return  # Termine la fonction après le yield

            # 3. Cas Standard (Clé sans liste 'values' ou liste vide)
            # Dans ce cas, nous renvoyons simplement l'événement de clé unique (LastWriteTime)

            # Tente de supprimer l'ancienne simplification du point 3 du code précédent (si elle existait)
            event.pop("value_data", None)
            event.pop("value_type", None)

            # S'assurer que le document final de la clé soit propre
            event.update(base_doc)
            self.drop_useless_fields(event)

            return event, "hive"

        except Exception as e:
            # En cas d'erreur de traitement, on retourne un document d'erreur clair
            error_doc = {
                "message": f"Registry key parsing failed: {e}",
                "raw_event_line": event.get("event_raw_string")
            }
            return error_doc, "hive"