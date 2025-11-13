#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoMftProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements MFT (fs:stat)."""

    def __init__(self):
        print("  [*] Initialisation du processeur MFT")

        # Mapping pour raccourcir les noms de timestamps MFT
        self.TIMESTAMP_TYPE_MAP = {
            "File Creation Time": "creation",
            "Content Modification Time": "modification",
            "Content Access Time": "access",
            "Entry Modification Time": "entry_modification",
            "Last Access Time": "access",
            "Creation Time": "creation",
        }

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement MFT de Plaso."""
        try:
            # 1. Gestion du Timestamp (FILETIME)
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Renommer le descripteur de timestamp (MODIFIÉ)
            if "timestamp_desc" in event:
                original_desc = event.pop("timestamp_desc")
                # Utiliser le mapping pour obtenir la version courte, sinon garder l'original
                event["mft_timestamp_type"] = self.TIMESTAMP_TYPE_MAP.get(original_desc, original_desc)

            # 3. NettoyageA
            self.drop_useless_fields(event)

            # 4. Clé d'index
            return event, "mft"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_mft_event: {e}")
            return self.drop_useless_fields(event), "mft"