#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from .base_processor import BaseEventProcessor


class PlasoRegistryProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements de Registre (winreg)."""

    def __init__(self):
        print("  [*] Initialisation du processeur Registre")
        # Copié de plaso_2_siem.py
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

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement de Registre de Plaso."""
        try:
            # 1. Identifier le type de hive
            filename = event.get("filename", "")
            specific_type = self.get_specific_hive_type(filename)
            if specific_type:
                # Ajoute le champ 'hive_type' (votre demande)
                event["hive_type"] = specific_type

            # 2. Logique de Timestamp (le FILETIME est roi)
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                # Fallback sur le timestamp plaso
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 3. Simplifier les valeurs
            values = event.get("values")
            if isinstance(values, list) and len(values) == 1:
                value_obj = values[0]
                # Gérer les valeurs par défaut (sans nom)
                if value_obj.get("name") == "":
                    event["value_data"] = value_obj.get("data")
                    event["value_type"] = value_obj.get("data_type")
                    event.pop("values", None)

            # 4. Nettoyage
            self.drop_useless_fields(event)

            # 5. Clé d'index (MODIFIÉ: Utilise un index unique "hive")
            index_key = "hive"
            return event, index_key

        except Exception as e:
            # print(f"[ERREUR] Échec de process_registry_event: {e}")
            return self.drop_useless_fields(event), "hive_other"