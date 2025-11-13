#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoMruProcessor(BaseEventProcessor):
    """Processeur Plaso pour les listes MRU (winreg/bagmru, winreg/mrulistex)."""

    def __init__(self):
        print("  [*] Initialisation du processeur MRU")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement MRU de Plaso."""
        try:
            # 1. Gestion du Timestamp
            # Le 'date_time' (FILETIME) est le LastWriteTime de la clé.
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Nettoyage
            # Les champs 'key_path', 'entries', 'shell_item_path' seront conservés.
            self.drop_useless_fields(event)

            # 3. Clé d'index
            return event, "mru"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_mru_event: {e}")
            return self.drop_useless_fields(event), "mru"