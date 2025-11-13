#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoLnkProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements LNK (windows:lnk:link)."""

    def __init__(self):
        print("  [*] Initialisation du processeur LNK")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement LNK de Plaso."""
        try:
            timestamp_desc = event.get("timestamp_desc", "")

            # 1. Gestion du Timestamp
            if timestamp_desc == "Not a time" or event.get("timestamp") == 0:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)
            else:
                # C'est un vrai timestamp (Creation, Modif, etc.)
                dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
                if dt_filetime:
                    event["estimestamp"] = self._format_dt_to_es(dt_filetime)
                else:
                    dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                    event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Renommer le descripteur
            if "timestamp_desc" in event:
                event["lnk_timestamp_type"] = event.pop("timestamp_desc")

            # 3. Nettoyage
            self.drop_useless_fields(event)

            # 4. Clé d'index
            return event, "lnk"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_lnk_event: {e}")
            return self.drop_useless_fields(event), "lnk"