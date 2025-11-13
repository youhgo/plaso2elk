#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoPrefetchProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements Prefetch (windows:prefetch:execution)."""

    def __init__(self):
        print("  [*] Initialisation du processeur Prefetch")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement Prefetch de Plaso."""
        try:
            # 1. Gestion du Timestamp (FILETIME)
            # Le champ 'date_time' (FILETIME) représente le 'Previous Last Time Executed'
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                # Fallback sur le timestamp plaso
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Renommer le descripteur de timestamp
            if "timestamp_desc" in event:
                event["prefetch_timestamp_type"] = event.pop("timestamp_desc")

            # 3. Nettoyage
            # Les champs 'executable', 'run_count', 'mapped_files', 'path_hints'
            # ne sont pas dans la liste 'drop_useless_fields', ils seront donc conservés.
            self.drop_useless_fields(event)

            # 4. Clé d'index
            return event, "prefetch"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_prefetch_event: {e}")
            return self.drop_useless_fields(event), "prefetch"