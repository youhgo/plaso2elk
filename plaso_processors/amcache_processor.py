#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoAmcacheProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements Amcache (winreg/amcache).
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Amcache")

    def process_event(self, event: dict) -> (dict, str):
        """
        Traite un événement Amcache de Plaso.
        """
        try:
            time_tuple = event.get("date_time", {}).get("time_elements_tuple")
            dt = self._parse_time_elements_to_dt(time_tuple)

            if not dt:
                dt = self._parse_unix_micro_to_dt(event.get("timestamp"))

            event["estimestamp"] = self._format_dt_to_es(dt)
            self.drop_useless_fields(event)
            index_key = 'amcache'
            return event, index_key

        except Exception as e:
            return {"message": f"Amcache parsing failed: {e}"}, "amcache_other"